package com.suivi.frigo.ble

/**
 * Statut décodé d'une trame envoyée par le frigo.
 * Voir la documentation de reverse engineering : protocole WT-0001 / Alpicool.
 */
data class FridgeStatus(
    val tempSet: Int,
    val fridgeTemp: Int,
    val batteryPct: Int,
    val voltage: Double,
    val locked: Boolean,
    val on: Boolean,
    val ecoMode: Boolean
)

object FridgeProtocol {

    val SERVICE_UUID = java.util.UUID.fromString("00001234-0000-1000-8000-00805f9b34fb")
    val NOTIFY_UUID = java.util.UUID.fromString("00000211-b2d1-43f0-9b88-960cebf8b91e")
    val WRITE_UUID = java.util.UUID.fromString("00000212-b2d1-43f0-9b88-960cebf8b91e")

    val PING_CMD = byteArrayOf(0xFE.toByte(), 0xFE.toByte(), 0x03, 0x01, 0x02, 0x00)

    /**
     * Décode une trame de statut brute reçue sur la caractéristique NOTIFY.
     * Retourne null si la trame ne correspond pas au format attendu (préambule / longueur).
     */
    fun parseStatus(bytes: ByteArray): FridgeStatus? {
        if (bytes.size < 22) return null
        if (bytes[0] != 0xFE.toByte() || bytes[1] != 0xFE.toByte()) return null
        if (bytes[2] != 0x21.toByte()) return null

        // En Kotlin, Byte est déjà signé (-128..127) : .toInt() suffit pour les champs signés.
        val tempSet = bytes[8].toInt()
        val fridgeTemp = bytes[18].toInt()
        val batteryPct = bytes[19].toInt() and 0xFF
        val voltsInt = bytes[20].toInt() and 0xFF
        val voltsDec = bytes[21].toInt() and 0xFF
        val voltage = Math.round((voltsInt + voltsDec / 10.0) * 10) / 10.0

        return FridgeStatus(
            tempSet = tempSet,
            fridgeTemp = fridgeTemp,
            batteryPct = batteryPct,
            voltage = voltage,
            locked = bytes[4] == 1.toByte(),
            on = bytes[5] == 1.toByte(),
            ecoMode = bytes[6] == 1.toByte()
        )
    }
}
