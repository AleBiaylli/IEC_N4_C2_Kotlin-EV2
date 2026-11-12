package com.example.appiot
import com.example.appiot.R
import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothDevice
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothSocket
import android.content.Context
import android.content.SharedPreferences
import android.content.pm.PackageManager
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import android.widget.Toast
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import java.io.IOException
import java.io.InputStream
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.UUID
import android.util.Log
class MainActivity : AppCompatActivity() {

    // 1. DECLARACIÓN DE COMPONENTES VISUALES (UI)
    private lateinit var layoutLogin: LinearLayout
    private lateinit var layoutDashboard: LinearLayout

    private lateinit var etUsername: EditText
    private lateinit var etPassword: EditText
    private lateinit var btnLogin: Button
    private lateinit var btnRegister: Button
    private lateinit var btnLogout: Button

    private lateinit var tvStatus: TextView
    private lateinit var tvTemperature: TextView
    private lateinit var tvHumidity: TextView
    private lateinit var tvHeatmapState: TextView
    private lateinit var cardHeatmap: LinearLayout
    private lateinit var btnConnect: Button

    // 2. ALMACENAMIENTO SEGURO MULTI-USUARIO (ISO 27400)
    private lateinit var securePrefs: SharedPreferences
    private var activeUsername: String? = null
    private var activeSessionPassword: String? = null // Solo en RAM para rotar el Salt al salir

    // 3. VARIABLES DE CONEXIÓN BLUETOOTH (PERFIL SPP / RFCOMM)
    private var bluetoothAdapter: BluetoothAdapter? = null
    private var bluetoothSocket: BluetoothSocket? = null
    private var inputStream: InputStream? = null

    @Volatile
    private var isConnected = false

    @Volatile
    private var isAutoConnectActive = false

    private val SPP_UUID: UUID = UUID.fromString("00001101-0000-1000-8000-00805F9B34FB")
    private val PERMISSION_REQUEST_CODE = 101

    // 4. CICLO DE VIDA INICIAL Y ENLACE DE VISTAS
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        securePrefs = getSharedPreferences("IoTSecureVault", Context.MODE_PRIVATE)
        val bluetoothManager = getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
        bluetoothAdapter = bluetoothManager.adapter

        // Enlace de contenedores y vistas
        layoutLogin = findViewById(R.id.layoutLogin)
        layoutDashboard = findViewById(R.id.layoutDashboard)

        etUsername = findViewById(R.id.etUsername)
        etPassword = findViewById(R.id.etPassword)
        btnLogin = findViewById(R.id.btnLogin)
        btnRegister = findViewById(R.id.btnRegister)
        btnLogout = findViewById(R.id.btnLogout)

        btnConnect = findViewById(R.id.btnConnect)
        tvStatus = findViewById(R.id.tvStatus)
        tvTemperature = findViewById(R.id.tvTemperature)
        tvHumidity = findViewById(R.id.tvHumidity)
        tvHeatmapState = findViewById(R.id.tvHeatmapState)
        cardHeatmap = findViewById(R.id.cardHeatmap)

        // Crea la cuenta base "admin" / "1234" solo si aún no existe en almacenamiento
        if (!userExists("admin")) {
            saveUserCredentials("admin", "1234")
        }

        // Evento Registrar: guarda múltiples usuarios distintos sin borrar los anteriores
        btnRegister.setOnClickListener {
            val user = etUsername.text.toString().trim()
            val pass = etPassword.text.toString()

            if (user.isEmpty() || pass.isEmpty()) {
                Toast.makeText(this, "Escribe usuario y clave para registrar", Toast.LENGTH_SHORT).show()
            } else {
                saveUserCredentials(user, pass)
                etPassword.text.clear()
                Toast.makeText(this, "Usuario '$user' guardado", Toast.LENGTH_SHORT).show()
            }
        }

        // Evento Iniciar Sesión
        btnLogin.setOnClickListener { authenticateUser() }

        // Evento Cerrar Sesión: rota el Salt del usuario activo para que su próximo hash sea distinto
        btnLogout.setOnClickListener {
            stopAllBluetoothActivity()

            val user = activeUsername
            val pass = activeSessionPassword
            if (!user.isNullOrEmpty() && !pass.isNullOrEmpty()) {
                saveUserCredentials(user, pass)
            }
            activeUsername = null
            activeSessionPassword = null

            etPassword.text.clear()
            layoutDashboard.visibility = View.GONE
            layoutLogin.visibility = View.VISIBLE
            Toast.makeText(this, "Sesión cerrada y Hash rotado", Toast.LENGTH_SHORT).show()
        }

        // Evento manual para desconectar o forzar búsqueda Bluetooth
        btnConnect.setOnClickListener {
            if (isConnected) {
                stopAllBluetoothActivity()
                updateStatusUI("Estado: Desconectado manualmente", "#757575")
            } else {
                startAutoConnectRoutine()
            }
        }
    }

    // 5. ALGORITMO DE REGISTRO Y AUTENTICACIÓN MULTI-USUARIO (SALTED SHA-256)
    private fun userExists(username: String): Boolean {
        return securePrefs.contains("HASH_$username")
    }

    private fun saveUserCredentials(username: String, rawPassword: String) {
        val salt = generateRandomSalt()
        val saltedHash = sha256WithSalt(rawPassword, salt)
        // Imprime en el Logcat de Android Studio (No visible en la pantalla del celular)
        Log.d("SEGURIDAD_IOT", "Usuario: $username | Nuevo Salt: $salt | Hash SHA-256: $saltedHash")
        // Indexa cada usuario por su nombre para mantener múltiples cuentas guardadas
        securePrefs.edit()
            .putString("SALT_$username", salt)
            .putString("HASH_$username", saltedHash)
            .apply()
    }

    private fun authenticateUser() {
        val inputUser = etUsername.text.toString().trim()
        val inputPass = etPassword.text.toString()

        if (inputUser.isEmpty() || inputPass.isEmpty()) {
            Toast.makeText(this, "Ingrese usuario y contraseña", Toast.LENGTH_SHORT).show()
            return
        }

        // Busca la sal y el hash específicos del usuario ingresado
        val savedSalt = securePrefs.getString("SALT_$inputUser", null)
        val savedHash = securePrefs.getString("HASH_$inputUser", null)

        if (savedSalt == null || savedHash == null) {
            Toast.makeText(this, "El usuario '$inputUser' no está registrado", Toast.LENGTH_SHORT).show()
            return
        }

        // Aplica SHA-256 combinando la contraseña ingresada con la Sal de ese usuario
        val computedHash = sha256WithSalt(inputPass, savedSalt)

        if (computedHash == savedHash) {
            activeUsername = inputUser
            activeSessionPassword = inputPass

            layoutLogin.visibility = View.GONE
            layoutDashboard.visibility = View.VISIBLE
            Toast.makeText(this, "Bienvenido, $inputUser", Toast.LENGTH_SHORT).show()

            if (checkAndRequestBluetoothPermissions()) {
                startAutoConnectRoutine()
            }
        } else {
            etPassword.text.clear()
            Toast.makeText(this, "Contraseña incorrecta", Toast.LENGTH_SHORT).show()
        }
    }

    // Genera una sal criptográfica aleatoria de 16 bytes en formato hexadecimal
    private fun generateRandomSalt(): String {
        val random = SecureRandom()
        val saltBytes = ByteArray(16)
        random.nextBytes(saltBytes)
        return saltBytes.joinToString("") { "%02x".format(it) }
    }

    // Combina la contraseña con la sal y calcula el resumen SHA-256
    private fun sha256WithSalt(password: String, salt: String): String {
        val combined = "$password:$salt"
        val bytes = MessageDigest.getInstance("SHA-256").digest(combined.toByteArray())
        return bytes.joinToString("") { "%02x".format(it) }
    }

    // 6. GESTIÓN DE PERMISOS GRANULARES (ANDROID 12+ / API 31+)
    private fun checkAndRequestBluetoothPermissions(): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            val permissionsNeeded = mutableListOf<String>()
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_CONNECT) != PackageManager.PERMISSION_GRANTED) {
                permissionsNeeded.add(Manifest.permission.BLUETOOTH_CONNECT)
            }
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.BLUETOOTH_SCAN) != PackageManager.PERMISSION_GRANTED) {
                permissionsNeeded.add(Manifest.permission.BLUETOOTH_SCAN)
            }
            if (permissionsNeeded.isNotEmpty()) {
                ActivityCompat.requestPermissions(this, permissionsNeeded.toTypedArray(), PERMISSION_REQUEST_CODE)
                return false
            }
        }
        return true
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == PERMISSION_REQUEST_CODE) {
            if (grantResults.isNotEmpty() && grantResults.all { it == PackageManager.PERMISSION_GRANTED }) {
                startAutoConnectRoutine()
            } else {
                updateStatusUI("Estado: Permisos Bluetooth denegados", "#D32F2F")
            }
        }
    }

    // 7. RUTINA MULTIHILO DE CONEXIÓN AUTOMÁTICA BLUETOOTH
    @SuppressLint("MissingPermission")
    private fun startAutoConnectRoutine() {
        if (isAutoConnectActive || isConnected) return
        isAutoConnectActive = true

        runOnUiThread {
            btnConnect.text = "Buscando módulo..."
            btnConnect.isEnabled = false
        }

        Thread {
            while (isAutoConnectActive && !isConnected) {
                if (bluetoothAdapter == null || !bluetoothAdapter!!.isEnabled) {
                    updateStatusUI("Estado: Bluetooth apagado. Enciéndelo para conectar", "#D32F2F")
                    Thread.sleep(3000)
                    continue
                }

                val pairedDevices: Set<BluetoothDevice>? = bluetoothAdapter?.bondedDevices
                val hcDevice = pairedDevices?.firstOrNull {
                    it.name?.contains("HC-05", true) == true || it.name?.contains("HC-06", true) == true
                }

                if (hcDevice == null) {
                    updateStatusUI("Estado: Módulo HC-05/HC-06 no vinculado en ajustes", "#E65100")
                    Thread.sleep(3000)
                    continue
                }

                try {
                    updateStatusUI("Estado: Intentando conectar con ${hcDevice.name}...", "#1976D2")
                    bluetoothSocket = hcDevice.createRfcommSocketToServiceRecord(SPP_UUID)
                    bluetoothSocket?.connect()

                    inputStream = bluetoothSocket?.inputStream
                    isConnected = true
                    isAutoConnectActive = false

                    runOnUiThread {
                        updateStatusUI("Estado: Conectado a ${hcDevice.name}", "#2E7D32")
                        btnConnect.text = "Desconectar"
                        btnConnect.isEnabled = true
                        Toast.makeText(this, "Módulo IoT activo y conectado", Toast.LENGTH_SHORT).show()
                    }

                    listenForData()

                } catch (e: IOException) {
                    try { bluetoothSocket?.close() } catch (_: IOException) {}
                    updateStatusUI("Estado: Módulo HC-05 inactivo. Reintentando...", "#E65100")
                    runOnUiThread { btnConnect.text = "Esperando módulo activo..." }
                    Thread.sleep(3000)
                }
            }
        }.start()
    }

    // 8. LECTURA SERIE, SANITIZACIÓN (REGEX) Y MAPA DE CALOR
    private fun listenForData() {
        val buffer = ByteArray(1024)
        var bytes: Int

        while (isConnected) {
            try {
                bytes = inputStream?.read(buffer) ?: -1
                if (bytes > 0) {
                    val rawData = String(buffer, 0, bytes)
                    parseAndDisplayData(rawData)
                }
            } catch (e: IOException) {
                isConnected = false
                runOnUiThread { resetTelemetryUI() }
                startAutoConnectRoutine()
                break
            }
        }
    }

    private fun parseAndDisplayData(data: String) {
        val tempRegex = Regex("T:([0-9.]+)")
        val humRegex = Regex("H:([0-9.]+)")

        val tempMatch = tempRegex.find(data)
        val humMatch = humRegex.find(data)

        runOnUiThread {
            tempMatch?.groupValues?.get(1)?.let { tempValStr ->
                tvTemperature.text = "Temp: $tempValStr °C"

                val tempVal = tempValStr.toDoubleOrNull() ?: 0.0
                when {
                    tempVal <= 24.0 -> {
                        tvHeatmapState.text = "Mapa de Calor: OPTIMO (LED Verde)"
                        tvHeatmapState.setTextColor(Color.parseColor("#2E7D32"))
                    }
                    tempVal in 24.1..28.0 -> {
                        tvHeatmapState.text = "Mapa de Calor: ADVERTENCIA (LED Amarillo)"
                        tvHeatmapState.setTextColor(Color.parseColor("#E65100"))
                    }
                    else -> {
                        tvHeatmapState.text = "Mapa de Calor: CRÍTICO (LED Rojo)"
                        tvHeatmapState.setTextColor(Color.parseColor("#C62828"))
                    }
                }
            }

            humMatch?.groupValues?.get(1)?.let { humVal ->
                tvHumidity.text = "Hum: $humVal %"
            }
        }
    }

    // 9. UTILIDADES DE INTERFAZ Y CIERRE SEGURO DE RECURSOS
    private fun updateStatusUI(message: String, colorHex: String) {
        runOnUiThread {
            tvStatus.text = message
            tvStatus.setTextColor(Color.parseColor(colorHex))
        }
    }

    private fun resetTelemetryUI() {
        tvTemperature.text = "Temp: -- °C"
        tvHumidity.text = "Hum: -- %"
        tvHeatmapState.text = "Mapa de Calor: -- (Esperando datos)"
        tvHeatmapState.setTextColor(Color.parseColor("#64748B"))
    }

    private fun stopAllBluetoothActivity() {
        isAutoConnectActive = false
        isConnected = false
        try {
            inputStream?.close()
            bluetoothSocket?.close()
        } catch (e: IOException) {
            e.printStackTrace()
        } finally {
            runOnUiThread {
                btnConnect.text = "Conectar / Reintentar Bluetooth"
                btnConnect.isEnabled = true
                resetTelemetryUI()
            }
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        stopAllBluetoothActivity()
    }
}