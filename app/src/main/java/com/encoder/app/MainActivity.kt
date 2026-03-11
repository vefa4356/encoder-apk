package com.encoder.app

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.OpenableColumns
import android.view.View
import android.widget.*
import java.io.*
import java.net.URL
import java.util.zip.ZipInputStream

class MainActivity : Activity() {

    private lateinit var btnDosyaSec: Button
    private lateinit var btnDurum: TextView
    private lateinit var logView: TextView
    private lateinit var progressBar: ProgressBar
    private lateinit var scrollView: ScrollView

    private val handler = Handler(Looper.getMainLooper())
    private val DOSYA_SEC_KOD = 1001

    private val ASSETS_URL = "https://github.com/vefa4356/encoder-assets/raw/master/apk_assets.zip"
    private val KURULUM_FLAG = "kuruldu_v2.flag"
    private val SCRIPT_ADI = "555.py"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        btnDosyaSec = findViewById(R.id.btnDosyaSec)
        btnDurum    = findViewById(R.id.btnDurum)
        progressBar = findViewById(R.id.progressBar)
        logView     = findViewById(R.id.logView)
        scrollView  = findViewById(R.id.scrollView)

        btnDosyaSec.isEnabled = false
        btnDosyaSec.text = "⏳ Hazırlanıyor..."

        Thread { kurulumKontrol() }.start()

        btnDosyaSec.setOnClickListener {
            val intent = Intent(Intent.ACTION_GET_CONTENT)
            intent.type = "*/*"
            intent.addCategory(Intent.CATEGORY_OPENABLE)
            startActivityForResult(Intent.createChooser(intent, ".py dosyası seç"), DOSYA_SEC_KOD)
        }
    }

    private fun kurulumKontrol() {
        val flagDosya = File(filesDir, KURULUM_FLAG)
        if (flagDosya.exists()) {
            log("✅ Kurulum mevcut, hazır!")
            ui {
                btnDosyaSec.isEnabled = true
                btnDosyaSec.text = "📂 .py Dosyası Seç"
                progressBar.visibility = View.GONE
            }
        } else {
            log("📦 İlk kurulum başlıyor...")
            indir()
        }
    }

    private fun indir() {
        ui {
            progressBar.visibility = View.VISIBLE
            progressBar.isIndeterminate = true
            btnDurum.text = "İndiriliyor..."
        }

        try {
            log("🌐 Assets indiriliyor...")
            val zipDosya = File(filesDir, "assets.zip")
            val url = URL(ASSETS_URL)
            val baglanti = url.openConnection()
            baglanti.connect()
            val toplam = baglanti.contentLength

            val giris = BufferedInputStream(url.openStream())
            val cikis = FileOutputStream(zipDosya)
            val tampon = ByteArray(8192)
            var indirilen = 0
            var okunan: Int

            while (giris.read(tampon).also { okunan = it } != -1) {
                cikis.write(tampon, 0, okunan)
                indirilen += okunan
                if (toplam > 0) {
                    val yuzde = (indirilen * 100 / toplam)
                    ui {
                        progressBar.isIndeterminate = false
                        progressBar.progress = yuzde
                        btnDurum.text = "İndiriliyor... %$yuzde"
                    }
                }
            }

            cikis.close()
            giris.close()
            log("✅ İndirme tamamlandı (${zipDosya.length() / 1024} KB)")
            kur(zipDosya)

        } catch (e: Exception) {
            log("❌ İndirme hatası: ${e.message}")
            ui { btnDurum.text = "Hata! Tekrar dene." }
        }
    }

    private fun kur(zipDosya: File) {
        ui { btnDurum.text = "Kurulum yapılıyor..." }
        log("📂 Dosyalar çıkarılıyor...")

        try {
            val zis = ZipInputStream(FileInputStream(zipDosya))
            var giris = zis.nextEntry

            while (giris != null) {
                val hedef = File(filesDir, giris.name)
                if (giris.isDirectory) {
                    hedef.mkdirs()
                } else {
                    hedef.parentFile?.mkdirs()
                    val fos = FileOutputStream(hedef)
                    val tampon = ByteArray(8192)
                    var okunan: Int
                    while (zis.read(tampon).also { okunan = it } != -1) {
                        fos.write(tampon, 0, okunan)
                    }
                    fos.close()
                }
                zis.closeEntry()
                giris = zis.nextEntry
            }
            zis.close()
            zipDosya.delete()

            File(filesDir, KURULUM_FLAG).createNewFile()
            log("✅ Kurulum tamamlandı!")

            ui {
                progressBar.visibility = View.GONE
                btnDosyaSec.isEnabled = true
                btnDosyaSec.text = "📂 .py Dosyası Seç"
                btnDurum.text = "Hazır"
            }

        } catch (e: Exception) {
            log("❌ Kurulum hatası: ${e.message}")
        }
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == DOSYA_SEC_KOD && resultCode == RESULT_OK) {
            val uri = data?.data ?: return
            val dosyaAdi = dosyaAdiAl(uri)

            if (!dosyaAdi.endsWith(".py")) {
                Toast.makeText(this, "Sadece .py dosyası!", Toast.LENGTH_SHORT).show()
                return
            }

            val hedef = File(filesDir, dosyaAdi)
            contentResolver.openInputStream(uri)?.use { giris ->
                FileOutputStream(hedef).use { cikis ->
                    giris.copyTo(cikis)
                }
            }
            derle(hedef)
        }
    }

    private fun derle(pyDosya: File) {
        btnDosyaSec.isEnabled = false
        btnDosyaSec.text = "⏳ Derleniyor..."
        logView.text = ""
        log("🚀 Derleme başladı: ${pyDosya.name}")

        Thread {
            try {
                val assetsDir = File(filesDir, "apk_assets")
                val scriptDosya = File(assetsDir, SCRIPT_ADI)
                val ciktiDosya = File(filesDir, "c.py")
                val pythonLib = File(assetsDir, "lib/python3.13")

                // nativeLibraryDir'den python3 çalıştır
                val nativeDir = applicationInfo.nativeLibraryDir
                val python3 = File(nativeDir, "libpython3_exec.so")

                log("🐍 Python3: ${python3.absolutePath}")
                log("📁 Native dir: $nativeDir")

                val env = arrayOf(
                    "PATH=${assetsDir.absolutePath}:$nativeDir:${System.getenv("PATH")}",
                    "HOME=${filesDir.absolutePath}",
                    "TMPDIR=${cacheDir.absolutePath}",
                    "ENCODER_ASSETS=${assetsDir.absolutePath}",
                    "ENCODER_OUT=${ciktiDosya.absolutePath}",
                    "PYTHONHOME=${assetsDir.absolutePath}",
                    "PYTHONPATH=${pythonLib.absolutePath}:${File(pythonLib, "site-packages").absolutePath}",
                    "LD_LIBRARY_PATH=${assetsDir.absolutePath}:$nativeDir:${System.getenv("LD_LIBRARY_PATH") ?: ""}"
                )

                val proc = Runtime.getRuntime().exec(
                    arrayOf(python3.absolutePath, scriptDosya.absolutePath),
                    env,
                    filesDir
                )

                proc.outputStream.bufferedWriter().use {
                    it.write(pyDosya.name + "\n")
                    it.flush()
                }

                Thread {
                    proc.errorStream.bufferedReader().forEachLine { satir ->
                        log("⚠ $satir")
                    }
                }.start()

                proc.inputStream.bufferedReader().forEachLine { satir ->
                    log(satir)
                }

                proc.waitFor()

                if (ciktiDosya.exists()) {
                    log("✅ Tamamlandı! c.py hazır.")
                    ui {
                        btnDurum.text = "✅ Tamamlandı!"
                        btnDosyaSec.isEnabled = true
                        btnDosyaSec.text = "📂 .py Dosyası Seç"
                        paylasButonaGoster(ciktiDosya)
                    }
                } else {
                    log("❌ c.py oluşturulamadı!")
                    ui {
                        btnDosyaSec.isEnabled = true
                        btnDosyaSec.text = "📂 .py Dosyası Seç"
                    }
                }

            } catch (e: Exception) {
                log("❌ Hata: ${e.message}")
                ui {
                    btnDosyaSec.isEnabled = true
                    btnDosyaSec.text = "📂 .py Dosyası Seç"
                }
            }
        }.start()
    }

    private fun paylasButonaGoster(cPy: File) {
        val btnPaylas = findViewById<Button>(R.id.btnPaylas)
        btnPaylas.visibility = View.VISIBLE
        btnPaylas.setOnClickListener {
            val uri = androidx.core.content.FileProvider.getUriForFile(
                this, "${packageName}.provider", cPy
            )
            val intent = Intent(Intent.ACTION_SEND)
            intent.type = "text/plain"
            intent.putExtra(Intent.EXTRA_STREAM, uri)
            intent.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
            startActivity(Intent.createChooser(intent, "c.py paylaş"))
        }
    }

    private fun dosyaAdiAl(uri: Uri): String {
        var ad = "dosya.py"
        contentResolver.query(uri, null, null, null, null)?.use { imle ->
            if (imle.moveToFirst()) {
                val idx = imle.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                if (idx >= 0) ad = imle.getString(idx)
            }
        }
        return ad
    }

    private fun log(mesaj: String) {
        handler.post {
            logView.append("$mesaj\n")
            scrollView.post { scrollView.fullScroll(View.FOCUS_DOWN) }
        }
    }

    private fun ui(blok: () -> Unit) {
        handler.post(blok)
    }
}
