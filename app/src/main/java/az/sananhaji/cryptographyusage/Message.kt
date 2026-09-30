package az.sananhaji.cryptographyusage

data class Message(
    val title: String,
    val description: String? = null,
    val properties: List<Property>? = null
)

data class Property(
    val title: String,
    val description: String
)
