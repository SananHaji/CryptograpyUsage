package az.sananhaji.cryptographyusage

import android.util.Log
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp

@Composable
fun MainScreen(modifier: Modifier) {
    val state = remember { mutableStateOf(listOf<String>()) }

    Column(modifier = modifier
        .fillMaxSize()
        .padding(24.dp)) {
        Column(modifier = Modifier.weight(1f)) {
            state.value.forEach {
                Text(it)
                Spacer(Modifier.height(16.dp))
            }
        }
        Button(
            modifier = Modifier.fillMaxWidth(),
            onClick = {
                val list = EncryptionProcessStepsGenerator.startProcess()
                Log.d("TAGTAGTAG", "MainScreen: list $list")
                state.value = list
            }) {
            Text("Prosesi Baslat")
        }
    }

}