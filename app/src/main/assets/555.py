import os, sys, re, ast, base64, hashlib, hmac, secrets, random
import subprocess, zipfile, shutil, threading, tempfile

NDK          = os.path.expanduser("~/ndk/android-ndk-r27d")
TOOLCHAIN    = f"{NDK}/toolchains/llvm/prebuilt/linux-x86_64"
SYSROOT      = f"{TOOLCHAIN}/sysroot"
TERMUX_USR   = "/data/data/com.termux/files/usr"
PYTHON32_INC = os.path.expanduser("~/python32_include")
PYTHON32_LIB = os.path.expanduser("~/python32_lib")
TERMUX_BIN   = f"{TERMUX_USR}/bin"
LLVM_STRIP   = f"{TERMUX_BIN}/llvm-strip"
LLVM_OBJCOPY = f"{TERMUX_BIN}/llvm-objcopy"
STRIP_FALLBACK = f"{TERMUX_BIN}/strip"

PK = "CYTHON"

                                                                              
PYVER_64 = "3.13"                               
PYVER_32 = "3.11"                                                             

                                                                              
ARM64_OUT    = "selectra"                            
ARM64_OUT_11 = "selectra11"                          
ARMV7_OUT    = "pegasus"                             
ARMV7_OUT_11 = "pegasus11"                           

ZIP_NAME   = ".56.zip"
LOADER_OUT = "/storage/emulated/0/c.py"

BOOTSTRAP = '''import os,sys,traceback as T
try:os.chdir(os.path.expanduser("~"))
except:pass
os.system("rm -rf ${TMPDIR:-/tmp}")
sys.excepthook=lambda*a:print(*[l for x in T.format_exception(*a) for l in x.splitlines() if not l.strip().startswith(("from ","import "))],sep=chr(10),file=sys.__stderr__)
'''

MIN_ENCRYPT_LEN = 4

SKIP_PATTERNS = re.compile(
    r'^(__\w+__|'
    r'utf-?8|ascii|'
    r'r\+?b?|wb?|rb?|a|'
    r'\d+(\.\d+)?|'
    r'[A-Z_]{2,}|'
    r'%[sdfr%]|'
    r'\\[ntr\\])'
    r'$'
)

def _xor_encrypt(text: str, key: bytes) -> bytes:
    raw = text.encode('utf-8')
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(raw))

class StringObfuscator:
    def __init__(self):
        self.entries: dict = {}
        self._counter = 0

    def _next_name(self) -> str:
        chars = 'abcdefghijklmnopqrstuvwxyz'
        n = ''.join(random.choices(chars, k=6)) + f"{self._counter:04x}"
        self._counter += 1
        return n

    def should_encrypt(self, s: str) -> bool:
        if len(s) < MIN_ENCRYPT_LEN:
            return False
        if SKIP_PATTERNS.match(s):
            return False
        if not any(c.isalpha() for c in s):
            return False
        return True

    def register(self, s: str) -> str:
        for name, (enc, key) in self.entries.items():
            dec = bytes(b ^ key[i % len(key)] for i, b in enumerate(enc))
            if dec == s.encode('utf-8'):
                return name
        name = self._next_name()
        key  = secrets.token_bytes(random.randint(8, 24))
        enc  = _xor_encrypt(s, key)
        self.entries[name] = (enc, key)
        return name

    def generate_python_prologue(self) -> str:
        lines = [
            "# -*- coding: utf-8 -*-",
        ]
        for name, (enc, key) in self.entries.items():
            enc_lit = repr(bytes(enc))
            key_lit = repr(bytes(key))
            lines.append(
                f"def _CYTHON_{name}():"
                f" _e={enc_lit}; _k={key_lit};"
                f" return bytes(_e[_i]^_k[_i%len(_k)] for _i in range(len(_e)))"
            )
        return "\n".join(lines) + "\n\n"

    def transform_python(self, source: str) -> str:
        """
        String literalleri tek tek şifreler.
        Her patch sonrası compile() ile doğrular — hata çıkarsa o patch'i geri alır.
        Bu sayede hiçbir zaman bozuk kod üretmez.
        """
        import tokenize, io

        try:
            src_lines = source.splitlines(True)
            tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
        except tokenize.TokenError:
            return source

        def offset(row, col):
            o = sum(len(src_lines[r]) for r in range(row - 1))
            return o + col

        candidates = []
        for tok in tokens:
            if tok.type != tokenize.STRING:
                continue
            processed = self._process_str_token(tok)
            if processed != tok.string:
                s = offset(*tok.start)
                e = offset(*tok.end)
                candidates.append((s, e, tok.string, processed))

        result = source
        for s, e, original, replacement in candidates:
            test = result[:s] + replacement + result[e:]
            prologue_now = self.generate_python_prologue()
            try:
                compile(prologue_now + test, "<check>", "exec")
                result = test
                diff = len(replacement) - (e - s)
                idx = candidates.index((s, e, original, replacement))
                for j in range(idx + 1, len(candidates)):
                    cs, ce, co, cr = candidates[j]
                    if cs >= e:
                        candidates[j] = (cs + diff, ce + diff, co, cr)
            except (SyntaxError, Exception):
                self.entries = {k: v for k, v in self.entries.items()
                               if bytes(b ^ v[1][i % len(v[1])] for i, b in enumerate(v[0])) != original.encode('utf-8', 'replace')}

        return result
    def _process_str_token(self, tok) -> str:
        try:
            val = ast.literal_eval(tok.string)
        except Exception:
            return tok.string
        if isinstance(val, str) and self.should_encrypt(val):
            name = self.register(val)
            return f"_CYTHON_{name}().decode('utf-8','replace')"
        return tok.string

def _fix_implicit_concat(source: str) -> str:
    """
    Satır başında + ile başlayan _CYTHON_xxx() çağrılarını düzelt.
    Örnek hatalı:  [
                    + _CYTHON_xxx().decode(...)
    Doğru:         [_CYTHON_xxx().decode(...)
    
    Ayrıca yan yana implicit concat'leri de + ile birleştir.
    """
    import re as _re
    
    source = _re.sub(
        r'(\n[ \t]*)\+ (_CYTHON_[a-z0-9]+\(\)\.decode\([^)]*\))',
        r'\1\2',
        source
    )
    source = _re.sub(
        r'([,\[{(]\n[ \t]*)\+ ',
        r'\1',
        source
    )
    source = _re.sub(
        r'(\n)([ \t]*)\+ (_CYTHON_[a-z0-9]+\(\))',
        r'\1\2\3',
        source
    )
    
    p1 = _re.compile(
        r'(_CYTHON_[a-z0-9]+\(\)\.decode\([^)]*\))'
        r'([ \t]+)'
        r'(_CYTHON_[a-z0-9]+\(\)\.decode\([^)]*\))'
    )
    prev = None
    while prev != source:
        prev = source
        source = p1.sub(r'\1 +\2\3', source)
    return source
def prepare_source(py_file: str) -> tuple:
    obf = StringObfuscator()

    with open(py_file, 'r', encoding='utf-8') as f:
        original = f.read()

    combined = BOOTSTRAP + "\n\n" + original

    print("  String analizi yapılıyor...")
    transformed = obf.transform_python(combined)
    transformed = _fix_implicit_concat(transformed)
    print(f"  {len(obf.entries)} string şifrelendi")

    prologue_check = obf.generate_python_prologue()
    prologue_line_count = prologue_check.count('\n') + 1
    t_lines = transformed.split('\n')
    orig_lines = combined.split('\n')
    fixed_lines = set()

    for _ in range(len(t_lines)):
        full_check = prologue_check + '\n'.join(t_lines)
        try:
            compile(full_check, "<check>", "exec")
            print(f"  \u2714 Syntax doğrulandı")
            break
        except SyntaxError as se:
            err_lineno = se.lineno or 0
            transformed_lineno = err_lineno - prologue_line_count
            if transformed_lineno in fixed_lines:
                transformed_lineno += 1
            if 0 < transformed_lineno <= len(t_lines) and 0 < transformed_lineno <= len(orig_lines):
                orig_line = orig_lines[transformed_lineno - 1]
                print(f"  \u26a0 Syntax hatası satır {transformed_lineno}: {se.msg}")
                print(f"    Orijinale dönüyor: {orig_line[:80]}")
                t_lines[transformed_lineno - 1] = orig_line
                fixed_lines.add(transformed_lineno)
            else:
                print(f"  \u26a0 Düzeltilemez syntax hatası (satır {err_lineno}), devam ediliyor.")
                break
    else:
        print(f"  \u26a0 Tüm denemeler tükendi.")
    transformed = '\n'.join(t_lines)
    bt = tempfile.mkdtemp(prefix="build_")
    os.chmod(bt, 0o700)

    prologue = obf.generate_python_prologue()
    print(f"  Python prologue: {len(prologue):,} byte ({len(obf.entries)} fonksiyon)")

    pk_path = os.path.join(bt, PK)
    final_source = prologue + transformed

    debug_path = os.path.join(os.path.dirname(py_file) or ".", "debug_cython_output.py")
    with open(debug_path, 'w', encoding='utf-8') as f:
        f.write(final_source)
    print(f"  [DEBUG] Transform çıktısı: {debug_path}")

    with open(pk_path, 'w', encoding='utf-8') as f:
        f.write(final_source)

    return pk_path, bt

def _get_version_macros(pyver_str: str) -> list:
    try:
        major, minor = (int(x) for x in pyver_str.split("."))
    except Exception:
        major, minor = sys.version_info.major, sys.version_info.minor

    macros = []
    if major == 3:
        if minor >= 13:
            macros += [
                "-DCYTHON_IMMORTAL_CONSTANTS=0",
                "-DCYTHON_USE_DICT_VERSIONS=0",
                "-DCYTHON_USE_SYS_MONITORING=0",
            ]
        elif minor == 12:
            macros += [
                "-DCYTHON_IMMORTAL_CONSTANTS=1",
                "-DCYTHON_USE_DICT_VERSIONS=0",
                "-DCYTHON_USE_SYS_MONITORING=0",
            ]
        elif minor == 11:
            macros += [
                "-DCYTHON_IMMORTAL_CONSTANTS=1",
                "-DCYTHON_USE_DICT_VERSIONS=1",
                "-DCYTHON_USE_SYS_MONITORING=0",
            ]
        else:
            macros += [
                "-DCYTHON_IMMORTAL_CONSTANTS=0",
                "-DCYTHON_USE_DICT_VERSIONS=1",
                "-DCYTHON_USE_SYS_MONITORING=0",
            ]
    return macros

ANTI_REVERSE_MACROS = [
    "-DCYTHON_COMPRESS_STRINGS=3",
    "-DCYTHON_REFNANNY=0",
    "-DCYTHON_CLINE_IN_TRACEBACK=0",
    "-DCYTHON_PROFILE=0",
    "-DCYTHON_TRACE=0",
    "-DCYTHON_TRACE_NOGIL=0",
    "-DCYTHON_NO_DOCSTRINGS=1",
    "-DCYTHON_WITHOUT_ASSERTIONS=1",
    "-DCYTHON_USE_MODULE_STATE=0",
    "-DCYTHON_NO_PYINIT_EXPORT=1",
    "-DCYTHON_HIDE_STACKFRAMES=1",
    "-DCYTHON_UPDATE_DESCRIPTOR_DOC=0",
    "-DNDEBUG=1",
]

PERFORMANCE_MACROS = [
    "-DCYTHON_METH_FASTCALL=1",
    "-DCYTHON_FAST_PYCALL=1",
    "-DCYTHON_FAST_PYCCALL=1",
    "-DCYTHON_VECTORCALL=1",
    "-DCYTHON_FAST_THREAD_STATE=1",
    "-DCYTHON_FAST_GIL=1",
    "-DCYTHON_USE_TYPE_SLOTS=1",
    "-DCYTHON_USE_ASYNC_SLOTS=1",
    "-DCYTHON_USE_TP_FINALIZE=1",
    "-DCYTHON_UNPACK_METHODS=1",
    "-DCYTHON_ASSUME_SAFE_MACROS=1",
    "-DCYTHON_ASSUME_SAFE_SIZE=1",
    "-DCYTHON_USE_PYLONG_INTERNALS=1",
    "-DCYTHON_USE_PYLIST_INTERNALS=1",
    "-DCYTHON_USE_UNICODE_INTERNALS=1",
    "-DCYTHON_USE_UNICODE_WRITER=1",
    "-DCYTHON_USE_PYTYPE_LOOKUP=1",
    "-DCYTHON_USE_FREELISTS=1",
    "-DCYTHON_AVOID_BORROWED_REFS=0",
    "-DCYTHON_USE_EXC_INFO_STACK=1",
    "-DCYTHON_ATOMICS=0",
    "-DCYTHON_PEP489_MULTI_PHASE_INIT=0",
    "-DCYTHON_FREETHREADING_COMPATIBLE=0",
    "-DCYTHON_CCOMPLEX=1",
]

CRITICAL_MACROS = [
    "-D__Pyx_TypeCheck(obj,type)=PyObject_TypeCheck(obj,type)",
    "-D__Pyx_IS_TYPE(ob,type)=(Py_TYPE(ob)==(type))",
    "-D__Pyx_Py_Is(x,y)=((x)==(y))",
    "-D__Pyx_Py_IsNone(ob)=((ob)==Py_None)",
    "-D__Pyx_Py_IsTrue(ob)=((ob)==Py_True)",
    "-D__Pyx_Py_IsFalse(ob)=((ob)==Py_False)",
    "-D__Pyx_PyList_GET_ITEM(o,i)=PyList_GET_ITEM(o,i)",
    "-D__Pyx_PyTuple_GET_ITEM(o,i)=PyTuple_GET_ITEM(o,i)",
    "-D__Pyx_PyList_SET_ITEM(o,i,v)=PyList_SET_ITEM(o,i,v)",
    "-D__Pyx_PyTuple_SET_ITEM(o,i,v)=PyTuple_SET_ITEM(o,i,v)",
    "-D__Pyx_PyList_GET_SIZE(o)=PyList_GET_SIZE(o)",
    "-D__Pyx_PyTuple_GET_SIZE(o)=PyTuple_GET_SIZE(o)",
    "-D__Pyx_PyBytes_GET_SIZE(o)=PyBytes_GET_SIZE(o)",
    "-D__Pyx_PyUnicode_GET_LENGTH(o)=PyUnicode_GET_LENGTH(o)",
    "-D__Pyx_PyUnicode_READY(op)=PyUnicode_READY(op)",
    "-D__Pyx_PyUnicode_KIND(u)=PyUnicode_KIND(u)",
    "-D__Pyx_PyUnicode_DATA(u)=PyUnicode_DATA(u)",
    "-D__Pyx_PyUnicode_IS_TRUE(u)=PyUnicode_GET_LENGTH(u)",
    "-D__Pyx_PyGILState_Ensure=PyGILState_Ensure",
    "-D__Pyx_PyGILState_Release=PyGILState_Release",
    "-D__Pyx_PyThreadState_Current=PyThreadState_GET()",
    "-D__Pyx_BUILTIN_MODULE_NAME=\"builtins\"",
    "-D__Pyx_DefaultClassType=PyType_Type",
    "-D__Pyx_PyCode_HasFreeVars(co)=(PyCode_GetNumFree(co)>0)",
    "-D__Pyx_PyFrame_SetLineNumber(frame,lineno)=((frame)->f_lineno=(lineno))",
    "-D__Pyx_METH_FASTCALL=METH_FASTCALL",
    "-D__Pyx_CyOrPyCFunction_Check(func)=PyCFunction_Check(func)",
    "-DCYTHON_INLINE=inline",
    "-DCYTHON_UNUSED=__attribute__((__unused__))",
    "-DCYTHON_RESTRICT=__restrict__",
    "-DCYTHON_FALLTHROUGH=__attribute__((fallthrough))",
    "-D__Pyx_INCREF=Py_INCREF",
    "-D__Pyx_DECREF=Py_DECREF",
    "-D__Pyx_XINCREF=Py_XINCREF",
    "-D__Pyx_XDECREF=Py_XDECREF",
    "-D__Pyx_PyException_Check(obj)=PyExceptionInstance_Check(obj)",
    "-DCO_COROUTINE=0x80",
    "-DCO_ASYNC_GENERATOR=0x200",
    "-DMETH_STACKLESS=0",
    "-DMETH_FASTCALL=0x80",
    "-DPy_TPFLAGS_CHECKTYPES=0",
    "-DPy_TPFLAGS_HAVE_INDEX=0",
    "-DPy_TPFLAGS_HAVE_NEWBUFFER=0",
    "-DPy_TPFLAGS_HAVE_FINALIZE=0",
    "-DPy_TPFLAGS_SEQUENCE=0",
    "-DPy_TPFLAGS_MAPPING=0",
]

WARNING_SUPPRESS = [
    "-w",
    "-Wno-deprecated-declarations",
    "-Wno-deprecated",
    "-Wno-unused-function",
    "-Wno-unused-variable",
    "-Wno-unused-parameter",
    "-Wno-unused-value",
    "-Wno-unused-result",
    "-Wno-missing-field-initializers",
    "-Wno-write-strings",
    "-Wno-return-type",
    "-Wno-format",
    "-Wno-format-security",
    "-Wno-strict-aliasing",
    "-Wno-attributes",
]

OPT_FLAGS_ARM64 = [
    "-Oz",
    "-fPIE", "-pie",
    "-march=armv8-a+crypto+crc",
    "-mtune=cortex-a55",
    "-fstack-protector-strong",
    "-U_FORTIFY_SOURCE",
    "-D_FORTIFY_SOURCE=2",
    "-fvisibility=hidden",
    "-fvisibility-inlines-hidden",
    "-ffunction-sections",
    "-fdata-sections",
    "-fomit-frame-pointer",
    "-flto=thin",
    "-fwhole-program-vtables",
    "-ffast-math",
    "-fno-math-errno",
    "-ffinite-math-only",
    "-funsafe-math-optimizations",
    "-fno-trapping-math",
    "-ftree-vectorize",
    "-finline-functions",
    "-finline-limit=300",
    "-fno-exceptions",
    "-fno-rtti",
    "-fno-threadsafe-statics",
    "-fmerge-all-constants",
    "-fmerge-constants",
    "-fno-ident",
    "-fno-asynchronous-unwind-tables",
    "-fno-unwind-tables",
    "-fno-plt",
    "-fPIC",
    "-fmacro-prefix-map=/data/data/com.termux/files/usr/include=.",
    "-fmacro-prefix-map=/data/data/com.termux/files/home=.",
    f"-fmacro-prefix-map={NDK}=.",
    "-g0",
]

OPT_FLAGS_ARMV7 = [
    "-Oz",
    "-fPIE", "-pie",
    "-mthumb",
    "-march=armv7-a",
    "-mfpu=neon-vfpv4",
    "-mfloat-abi=softfp",
    "-mtune=cortex-a9",
    "-fstack-protector-strong",
    "-U_FORTIFY_SOURCE",
    "-D_FORTIFY_SOURCE=2",
    "-fvisibility=hidden",
    "-fvisibility-inlines-hidden",
    "-ffunction-sections",
    "-fdata-sections",
    "-fomit-frame-pointer",
    "-flto=thin",
    "-fwhole-program-vtables",
    "-ffast-math",
    "-fno-math-errno",
    "-ffinite-math-only",
    "-funsafe-math-optimizations",
    "-fno-trapping-math",
    "-ftree-vectorize",
    "-finline-functions",
    "-finline-limit=300",
    "-fno-exceptions",
    "-fno-rtti",
    "-fno-threadsafe-statics",
    "-fmerge-all-constants",
    "-fmerge-constants",
    "-fno-ident",
    "-fno-asynchronous-unwind-tables",
    "-fno-unwind-tables",
    "-fno-plt",
    "-fPIC",
    "-fmacro-prefix-map=/data/data/com.termux/files/usr/include=.",
    "-fmacro-prefix-map=/data/data/com.termux/files/home=.",
    f"-fmacro-prefix-map={NDK}=.",
    "-g0",
]

LINKER_FLAGS = [
    "-Wl,--gc-sections",
    "-Wl,--icf=all",
    "-Wl,-O2",
    "-Wl,--strip-all",
    "-Wl,--discard-all",
    "-Wl,--exclude-libs,ALL",
    "-Wl,--allow-shlib-undefined",
    "-Wl,-z,relro",
    "-Wl,-z,now",
    "-Wl,-z,noexecstack",
    "-Wl,-z,separate-code",
    "-Wl,--hash-style=gnu",
    "-Wl,--build-id=none",
    "-Wl,--as-needed",
    "-Wl,--relax",
    "-s",
]

LINKER_FLAGS_ARMV7 = LINKER_FLAGS + [
    "-Wl,--relax",
]

REMOVE_SECTIONS = [
    "--remove-section=.note.gnu.build-id",
    "--remove-section=.note.ABI-tag",
    "--remove-section=.note.GNU-stack",
    "--remove-section=.note",
    "--remove-section=.eh_frame",
    "--remove-section=.eh_frame_hdr",
    "--remove-section=.gcc_except_table",
    "--remove-section=.gdb_index",
    "--remove-section=.gnu_debuglink",
    "--remove-section=.gnu_debugdata",
    "--remove-section=.ARM.attributes",
    "--remove-section=.debug_str",
    "--remove-section=.debug_info",
    "--remove-section=.debug_line",
    "--remove-section=.debug_abbrev",
    "--remove-section=.debug_aranges",
    "--remove-section=.debug_ranges",
    "--remove-section=.debug_loc",
    "--remove-section=.debug_pubnames",
    "--remove-section=.debug_pubtypes",
    "--remove-section=.debug_frame",
    "--remove-section=.debug_macinfo",
    "--remove-section=.debug_macro",
    "--remove-section=.zdebug_info",
    "--remove-section=.zdebug_abbrev",
    "--remove-section=.zdebug_str",
    "--rename-section=.rodata=.data.r",
    "--rename-section=.text=.tx",
]

def run(cmd, desc="", ignore_error=False):
    print(f"\n▶ {desc or ' '.join(str(c) for c in cmd)}")
    result = subprocess.run(cmd, text=True)
    if result.returncode != 0 and not ignore_error:
        print(f"[HATA] Çıkış kodu: {result.returncode}")
        sys.exit(result.returncode)
    return result.returncode

def get_pyver():
    v = sys.version_info
    return f"{v.major}.{v.minor}"

def file_size(path):
    if os.path.exists(path):
        sz = os.path.getsize(path)
        return f"{sz / 1024:.1f} KB ({sz:,} byte)"
    return "?"

def find_tool(*candidates):
    for tool in candidates:
        if not tool:
            continue
        if os.path.isfile(tool) and os.access(tool, os.X_OK):
            return tool
        found = shutil.which(os.path.basename(tool))
        if found:
            return found
    return None

def cython_compile(py_file: str) -> str:
    base   = os.path.splitext(py_file)[0]
    c_file = f"{base}.c"

    if os.path.exists(c_file):
        os.remove(c_file)
        print(f"✔ Eski {c_file} temizlendi")

    print("\n── String Obfuscation ──")
    pk_path, bt = prepare_source(py_file)

    try:

        cython_cmd = [
            "cython", "--embed", "-3", "--no-docstrings",
            "-X", "boundscheck=False",
            "-X", "wraparound=False",
            "-X", "initializedcheck=False",
            "-X", "nonecheck=False",
            "-X", "overflowcheck=False",
            "-X", "cdivision=True",
            "-X", "always_allow_keywords=False",
            "-X", "profile=False",
            "-X", "linetrace=False",
            "-X", "language_level=3",
            "-X", "infer_types=True",
            "-X", "optimize.use_switch=True",
            "-X", "optimize.unpack_method_calls=True",
            "-X", "warn.undeclared=False",
            "-X", "warn.unreachable=False",
            "-X", "warn.maybe_uninitialized=False",
            "--directive", "binding=False",
            "--directive", "embedsignature=False",
            "--directive", "emit_code_comments=False",
            "--directive", "annotation_typing=False",
            "--directive", "c_string_type=bytes",
            "--directive", "c_string_encoding=default",
            pk_path, "-o", c_file,
        ]

        run(cython_cmd, f"Cython: {pk_path} → {c_file}")

        if not os.path.exists(c_file):
            print(f"[HATA] {c_file} oluşturulamadı!")
            sys.exit(1)

        _strip_c_comments(c_file)
        _protect_zlib_in_c(c_file)
        print(f"✔ .c dosyası hazır: {c_file}")
        return c_file
    except Exception as e:
        raise e
    finally:
        shutil.rmtree(bt, ignore_errors=True)

def _strip_c_comments(c_file):
    with open(c_file, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()
    content = re.sub(r'/\*\s*Generated by Cython[^\*]*\*/', '/* [redacted] */', content)
    content = re.sub(r'/\*\s*"\\/[^"]*":\d+[^\*]*\*/', '', content)
    with open(c_file, 'w', encoding='utf-8') as f:
        f.write(content)
    print("✔ C metadata temizlendi")

def _protect_zlib_in_c(c_file):
    with open(c_file, 'r', encoding='utf-8', errors='replace') as f:
        content = f.read()

    def parse_c_string(raw):
        parts = re.findall(r'"((?:[^"\\]|\\.)*)"', raw, re.DOTALL)
        out = bytearray()
        for part in parts:
            i = 0
            while i < len(part):
                if part[i] == '\\' and i + 1 < len(part):
                    c = part[i+1]
                    if c == 'x' and i + 3 < len(part):
                        out.append(int(part[i+2:i+4], 16)); i += 4
                    elif c.isdigit():
                        j, os_ = i+1, ''
                        while j < len(part) and part[j].isdigit() and len(os_) < 3:
                            os_ += part[j]; j += 1
                        out.append(int(os_, 8) & 0xFF); i = j
                    elif c == 'n':  out.append(10); i += 2
                    elif c == 'r':  out.append(13); i += 2
                    elif c == 't':  out.append(9);  i += 2
                    elif c == '\\': out.append(92); i += 2
                    elif c == '"':  out.append(34); i += 2
                    else:           out.append(ord(c) & 0xFF); i += 2
                else:
                    try: out.append(ord(part[i]))
                    except: pass
                    i += 1
        return bytes(out)

    cstring_re = re.compile(
        r'const char\* const cstring = ((?:"(?:[^"\\]|\\.)*"\s*)+);',
        re.DOTALL
    )

    matches = list(cstring_re.finditer(content))
    if not matches:
        print("  [BİLGİ] cstring bloğu bulunamadı")
        return

    header_blocks = []
    patches = []

    for idx, match in enumerate(matches):
        raw = parse_c_string(match.group(1))
        if len(raw) < 8:
            continue

        xor_key   = secrets.token_bytes(32)
        key_c     = ', '.join(f'0x{b:02x}' for b in xor_key)
        scrambled = bytes(b ^ xor_key[i % 32] for i, b in enumerate(raw))
        scr_len   = len(scrambled)

        chunks  = ['"{}"'.format(''.join(f'\\x{b:02x}' for b in scrambled[i:i+64]))
                   for i in range(0, scr_len, 64)]
        scr_lit = '\n'.join(chunks)

        uid = '_' + ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=4)) + ''.join(random.choices('0123456789abcdefABCDEF', k=4)) + ''.join(random.choices('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ', k=4))

        header_blocks.append(
            f"static const unsigned char {uid}_k[32] = {{{key_c}}};\n"
            f"static unsigned char {uid}_b[{scr_len} + 1];\n"
            f"static int {uid}_r = 0;\n"
            f"static const char* {uid}(void) {{\n"
            f"    if (!{uid}_r) {{\n"
            f"        static const unsigned char _s[] =\n{scr_lit};\n"
            f"        for (int _i = 0; _i < {scr_len}; _i++)\n"
            f"            {uid}_b[_i] = _s[_i] ^ {uid}_k[_i % 32];\n"
            f"        {uid}_b[{scr_len}] = 0;\n"
            f"        {uid}_r = 1;\n"
            f"    }}\n"
            f"    return (const char*){uid}_b;\n"
            f"}}\n"
        )

        patches.append((match.start(), match.end(),
                        f"const char* const cstring = {uid}();"))

    if not patches:
        print("  [BİLGİ] Geçerli cstring bulunamadı")
        return

    for start, end, repl in sorted(patches, key=lambda x: x[0], reverse=True):
        content = content[:start] + repl + content[end:]

    insert_marker = '#include "Python.h"'
    header_code = "\n" + "".join(header_blocks)
    if insert_marker in content:
        content = content.replace(insert_marker, insert_marker + header_code, 1)
    else:
        content = header_code + content

    with open(c_file, 'w', encoding='utf-8') as f:
        f.write(content)

    print(f"  ✔ {len(patches)} cstring XOR korumasına alındı")

def _all_macros(pyver_str: str) -> list:
    return ANTI_REVERSE_MACROS + PERFORMANCE_MACROS + CRITICAL_MACROS + _get_version_macros(pyver_str)

def compile_arm64(c_file, out_file, pyver):
    clang = f"{TOOLCHAIN}/bin/aarch64-linux-android21-clang"
    inc   = f"{TERMUX_USR}/include/python{pyver}"
    lib   = f"{TERMUX_USR}/lib"

    cmd = [
        clang,
        "-std=c11",
        f"-I{inc}",
        f"--sysroot={SYSROOT}",
        *OPT_FLAGS_ARM64,
        *WARNING_SUPPRESS,
        *_all_macros(pyver),
        c_file,
        f"-L{lib}",
        f"-lpython{pyver}",
        "-lm", "-ldl",
        *LINKER_FLAGS,
        "-o", out_file,
    ]
    run(cmd, f"ARM64/{pyver} → {out_file}")
    print(f"✔ ARM64/{pyver}: {out_file} [{file_size(out_file)}]")

def compile_armv7(c_file, out_file, pyver):
    clang        = f"{TOOLCHAIN}/bin/armv7a-linux-androideabi21-clang"
    inc          = f"{PYTHON32_INC}/python{pyver}"
    lib          = f"{PYTHON32_LIB}/python{pyver}"
    sysroot_lib  = f"{SYSROOT}/usr/lib/arm-linux-androideabi/21"
    clang_rt_lib = f"{TOOLCHAIN}/lib/clang/18/lib/linux/arm"

    cmd = [
        clang,
        "-std=c11",
        f"-I{inc}",
        f"--sysroot={SYSROOT}",
        *OPT_FLAGS_ARMV7,
        *WARNING_SUPPRESS,
        *_all_macros(pyver),
        c_file,
        f"-L{sysroot_lib}",
        f"-L{clang_rt_lib}",
        f"-L{lib}",
        f"-lpython{pyver}",
        "-lm", "-ldl",
        *LINKER_FLAGS_ARMV7,
        "-Wl,--unresolved-symbols=ignore-all",
        "-o", out_file,
    ]
    run(cmd, f"ARMv7/{pyver} → {out_file}")
    print(f"✔ ARMv7/{pyver}: {out_file} [{file_size(out_file)}]")

def compile_parallel(c_file):
    errors = []

    def _arm64_13():
        try: compile_arm64(c_file, ARM64_OUT, PYVER_64)
        except SystemExit as e: errors.append(f"ARM64/{PYVER_64}: {e}")

    def _arm64_11():
        try: compile_arm64(c_file, ARM64_OUT_11, PYVER_32)
        except SystemExit as e: errors.append(f"ARM64/{PYVER_32}: {e}")

    def _armv7_13():
        try: compile_armv7(c_file, ARMV7_OUT, PYVER_64)
        except SystemExit as e: errors.append(f"ARMv7/{PYVER_64}: {e}")

    def _armv7_11():
        try: compile_armv7(c_file, ARMV7_OUT_11, PYVER_32)
        except SystemExit as e: errors.append(f"ARMv7/{PYVER_32}: {e}")

    threads = [
        threading.Thread(target=_arm64_13),
        threading.Thread(target=_arm64_11),
        threading.Thread(target=_armv7_13),
        threading.Thread(target=_armv7_11),
    ]
    for t in threads: t.start()
    for t in threads: t.join()

    if errors:
        for e in errors: print(f"[HATA] {e}")
        sys.exit(1)

def optimize_binary(binary, arch):
    print(f"\n─── Strip + Scrub: {binary} ({arch}) ───")
    before = file_size(binary)

    strip_tool = find_tool(LLVM_STRIP, STRIP_FALLBACK)
    if not strip_tool:
        print("  [UYARI] llvm-strip / strip bulunamadı → 'pkg install llvm binutils'")
    else:
        run([strip_tool, "--strip-debug", "--strip-unneeded", binary], ignore_error=True)

    objcopy_tool = find_tool(LLVM_OBJCOPY)
    if objcopy_tool:
        run([objcopy_tool, *REMOVE_SECTIONS, binary], ignore_error=True)
        run([objcopy_tool,
             "--remove-section=.hash",
             "--remove-section=.gnu.version",
             binary], ignore_error=True)

    _scrub_strings(binary, [
        b"/data/data/com.termux",
        b"Generated by Cython",
    ])

    print(f"✔ {before} → {file_size(binary)}")

def _scrub_strings(binary_path, targets):
    with open(binary_path, 'r+b') as f:
        data = bytearray(f.read())
        changed = 0
        for target in targets:
            idx = 0
            while True:
                pos = data.find(target, idx)
                if pos == -1: break
                for i in range(len(target)):
                    data[pos + i] = 0
                changed += 1
                idx = pos + 1
        if changed:
            f.seek(0); f.write(data)
            print(f"  ✔ {changed} artık string scrub edildi")

def check_elf(files):
    print("\n─── ELF Kontrol ───")
    readelf = find_tool(
        f"{TERMUX_BIN}/llvm-readelf", f"{TERMUX_BIN}/readelf",
        "llvm-readelf", "readelf"
    )
    for f in files:
        r = subprocess.run(["file", f], capture_output=True, text=True)
        print(r.stdout.strip())
        if readelf:
            r2 = subprocess.run([readelf, "-d", f], capture_output=True, text=True)
            for line in r2.stdout.splitlines():
                if "NEEDED" in line or "FLAGS" in line:
                    print(f"  {line.strip()}")

    print("\n─── Canary / Fortify Kontrol ───")
    for f in files:
        result = subprocess.run(
            ["readelf", "-s", f],
            capture_output=True, text=True, errors="replace"
        )
        chk_symbols = [
            line for line in result.stdout.splitlines()
            if "_chk" in line or "__stack_chk" in line
        ]
        if chk_symbols:
            print(f"  ✔ {os.path.basename(f)}: Canary/Fortify AKTİF ({len(chk_symbols)} sembol)")
            for s in chk_symbols[:5]:
                print(f"      {s.strip()}")
        else:
            print(f"  ⚠ {os.path.basename(f)}: Sembol bulunamadı (STRIPPED olabilir)")

def mask_zlib_in_elf(elf_path):
    MAGIC = {(0x78, 0xDA), (0x78, 0x9C), (0x78, 0x5E), (0x78, 0x01)}
    MASK  = 0x61

    with open(elf_path, 'rb') as f:
        data = bytearray(f.read())

    offsets = []
    i = 0
    while i < len(data) - 1:
        if (data[i], data[i+1]) in MAGIC:
            data[i]   ^= MASK
            data[i+1] ^= MASK
            offsets.append(i)
            i += 2
        else:
            i += 1

    with open(elf_path, 'wb') as f:
        f.write(data)

    print(f"  ✔ {len(offsets)} zlib magic byte maskelendi → {os.path.basename(elf_path)}")
    return offsets

def make_main_py(offsets: dict):
    λ = {
        'selectra':   offsets.get('a64',    []),
        'selectra11': offsets.get('a64_11', []),
        'pegasus':    offsets.get('a32',    []),
        'pegasus11':  offsets.get('a32_11', []),
    }
    λ_repr = repr(λ)

    return (
        "import os as C,sys as D,zipfile as I,tempfile as L,shutil as K,fcntl as X,platform as M\n"
        "def B():\n"
        f" λ={λ_repr}\n"
        " φ=lambda p,n:(lambda d:([d.__setitem__(o,d[o]^97)or d.__setitem__(o+1,d[o+1]^97)for o in λ[n]if o+1<len(d)],open(p,'wb').write(bytes(d))))(bytearray(open(p,'rb').read()))\n"
        " G=lambda f:X.fcntl(f,X.F_SETFD,X.fcntl(f,X.F_GETFD)&~X.FD_CLOEXEC)\n"
        " d=L.mkdtemp();[I.ZipFile(D.argv[0],'r').__enter__().extractall(d)]\n"
        " F=M.machine();v=D.version_info;s='' if(v.major,v.minor)>=(3,12) else '11'\n"
        " J={'armv7l':'pegasus','armv8l':'pegasus','arm':'pegasus','aarch64':'selectra','arm64':'selectra'}\n"
        " if F not in J:D.exit(1)\n"
        " e=C.path.join(d,J[F]+s);C.chmod(e,0o755);φ(e,J[F]+s);f=C.open(e,C.O_RDONLY);G(f)\n"
        " C.system('export PYTHONHOME='+D.prefix+' && export PYTHON_EXECUTABLE='+D.executable+' && export LD_LIBRARY_PATH='+D.prefix+'/lib:$LD_LIBRARY_PATH && exec /proc/self/fd/'+str(f));K.rmtree(d,ignore_errors=True)\n"
        "if __name__=='__main__':B()"
    )

def make_payload_zip(zip_path, offsets: dict):
    print(f"\n▶ ZIP: {zip_path}")
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for arc, path in [
            (ARM64_OUT,    ARM64_OUT),
            (ARM64_OUT_11, ARM64_OUT_11),
            (ARMV7_OUT,    ARMV7_OUT),
            (ARMV7_OUT_11, ARMV7_OUT_11),
        ]:
            zf.write(path, arcname=arc)
            print(f"  + {arc} [{file_size(path)}]")
        zf.writestr("__main__.py", make_main_py(offsets))
        print(f"  + __main__.py")
    print(f"✔ ZIP: {file_size(zip_path)}")

def encode_zip(zip_path):
    with open(zip_path, 'rb') as f:
        data = f.read()
    hmac_key = secrets.token_bytes(32)
    mac      = hmac.new(hmac_key, data, hashlib.sha256).digest()
    payload  = b"RD03" + mac + data
    encoded  = base64.a85encode(base64.b64encode(payload), adobe=True).decode()
    return encoded, base64.b64encode(hmac_key).decode()

def make_loader(encoded_data, hmac_key_b64, out_path):
    code = (
        "import os,sys,base64 as β,hmac,hashlib\n"
        "ζ='𝑀𝑒𝑔𝑎'\n"
        f"δ={repr(encoded_data)}\n"
        f"κ={repr(hmac_key_b64)}\n"
        "try:\n"
        "\traw=β.b64decode(β.a85decode(δ.encode(),adobe=True))\n"
        "\tassert raw[:4]==b'RD03'\n"
        "\tkey=β.b64decode(κ)\n"
        "\tassert hmac.compare_digest(raw[4:36],hmac.new(key,raw[36:],hashlib.sha256).digest())\n"
        "\topen(ζ,'wb').write(raw[36:])\n"
        "\tos.system('python3 '+ζ+' '+' '.join(sys.argv[1:]))\n"
        "except:sys.exit(1)\n"
        "finally:\n"
        "\tos.path.exists(ζ)and os.remove(ζ)\n"
    )
    with open(out_path, 'w', encoding='utf-8') as f:
        f.write(code)
    print(f"✔ Loader: {out_path} [{file_size(out_path)}]")

def main():
    print("╔══════════════════════════════════════════════════════╗")
    print("║  Cython + NDK Derleyici — RD v5                      ║")
    print("║  4x Binary · Oz+LTO · XOR · Scrub · zlib · HMAC     ║")
    print("║  ARM64×2 + ARMv7×2  (Python 3.13 + 3.11)            ║")
    print("╚══════════════════════════════════════════════════════╝\n")

    py_file = input("Derlenecek .py dosyası: ").strip()
    if not py_file.endswith(".py"):
        py_file += ".py"
    if not os.path.isfile(py_file):
        print(f"[HATA] Bulunamadı: {py_file}")
        sys.exit(1)

    base   = os.path.splitext(py_file)[0]
    c_file = f"{base}.c"

    print(f"NDK      : {NDK}")
    print(f"Python64 : {PYVER_64}  →  {ARM64_OUT}, {ARMV7_OUT}")
    print(f"Python32 : {PYVER_32}  →  {ARM64_OUT_11}, {ARMV7_OUT_11}\n")

    print("══ AŞAMA 1: CYTHON ══")
    c_file = cython_compile(py_file)

    print("\n══ AŞAMA 2: PARALEL DERLEME (4x Binary) ══")
    compile_parallel(c_file)

    print("\n══ AŞAMA 3: STRIP + SCRUB ══")
    optimize_binary(ARM64_OUT,    f"ARM64/{PYVER_64}")
    optimize_binary(ARM64_OUT_11, f"ARM64/{PYVER_32}")
    optimize_binary(ARMV7_OUT,    f"ARMv7/{PYVER_64}")
    optimize_binary(ARMV7_OUT_11, f"ARMv7/{PYVER_32}")

    print("\n══ AŞAMA 3.5: ZLİB MASKELEME ══")
    offsets = {
        "a64":    mask_zlib_in_elf(ARM64_OUT),
        "a64_11": mask_zlib_in_elf(ARM64_OUT_11),
        "a32":    mask_zlib_in_elf(ARMV7_OUT),
        "a32_11": mask_zlib_in_elf(ARMV7_OUT_11),
    }

    print("\n══ AŞAMA 4: ELF KONTROL ══")
    check_elf([ARM64_OUT, ARM64_OUT_11, ARMV7_OUT, ARMV7_OUT_11])

    print("\n══ AŞAMA 5: ZIP ══")
    make_payload_zip(ZIP_NAME, offsets)

    print("\n══ AŞAMA 6: ENCODE + HMAC ══")
    encoded, hmac_key = encode_zip(ZIP_NAME)
    print(f"✔ {len(encoded):,} karakter")

    print("\n══ AŞAMA 7: LOADER ══")
    make_loader(encoded, hmac_key, LOADER_OUT)

    for tmp in [ZIP_NAME, ARM64_OUT, ARM64_OUT_11, ARMV7_OUT, ARMV7_OUT_11, c_file]:
        if os.path.exists(tmp):
            os.remove(tmp)

    print(f"\n✅ Tamamlandı → {LOADER_OUT} [{file_size(LOADER_OUT)}]")

if __name__ == "__main__":
    main()
