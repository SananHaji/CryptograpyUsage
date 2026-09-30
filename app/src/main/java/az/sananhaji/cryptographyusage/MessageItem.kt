package az.sananhaji.cryptographyusage

import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.height
import androidx.compose.material3.HorizontalDivider
import androidx.compose.material3.Text
import androidx.compose.material3.VerticalDivider
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp

@Composable
fun MessageItem(message: Message) {
    Column {
        Text(message.title, fontWeight = FontWeight.Bold)
        message.description?.let {
            Text(message.description, fontStyle = FontStyle.Italic)
        }

        message.properties?.let {
            Column {
                message.properties.forEach { property ->
                    Row {
                        Text(text = property.title, fontWeight = FontWeight.Bold)
                        Text(text = property.description)
                    }

                }
            }
        }
        HorizontalDivider(thickness = 1.dp)
        Spacer(Modifier.height(16.dp))
    }
}