package com.praphull.experiments.fido.client

import android.util.JsonReader
import android.util.JsonToken
import android.util.JsonWriter
import android.util.Log
import com.google.android.gms.fido.fido2.api.common.*
import com.google.android.gms.tasks.Task
import com.google.android.gms.tasks.Tasks
import com.praphull.experiments.fido.client.model.Credential
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.RequestBody.Companion.toRequestBody
import okio.ByteString.Companion.decodeBase64
import java.io.StringReader
import java.io.StringWriter
import java.util.concurrent.Executor
import java.util.concurrent.TimeUnit

class FidoHttpClient {

    companion object {
        private const val BaseUrl = "https://fido2.apps.praphull.com/auth/fido2"
        private const val RegistrationChallengeUrl = "$BaseUrl/attestation/options?platform_only=true"
        private const val RegistrationUrl = "$BaseUrl/register"
        private const val LoginChallengeUrl = "$BaseUrl/assertion/options"
        private const val LoginUrl = "$BaseUrl/login"
        private val JSON = "application/json".toMediaTypeOrNull()
        private const val TAG = "AuthApi"
        private const val HeaderUserTokenKey = "X-USER-TOKEN"
        private const val HeaderUserIdKey = "X-USER-ID"
    }


    private val client = OkHttpClient.Builder()
            .addInterceptor(HeaderInterceptor())
            .readTimeout(30, TimeUnit.SECONDS)
            .writeTimeout(40, TimeUnit.SECONDS)
            .connectTimeout(40, TimeUnit.SECONDS)
            .build()

    fun getRegistrationOptions(userId: Long, executor: Executor): Task<Response> {
        val call = client.newCall(
                Request.Builder()
                        .url(RegistrationChallengeUrl)
                        .addHeader(HeaderUserTokenKey, userId.toString())
                        .get()
                        /*.method("POST", jsonRequestBody {
                            name("attestation").value("none")
                            name("authenticatorSelection").objectValue {
                                name("authenticatorAttachment").value("platform")
                                name("userVerification").value("required")
                            }
                        })*/
                        .build()
        )

        return Tasks.call(executor, { call.execute() })
    }

    fun registerResponse(
            userId: Long,
            response: AuthenticatorAttestationResponse,
            executor: Executor
    ): Task<List<Credential>>? {

        val rawId = response.keyHandle.toBase64()
        val call = client.newCall(
                Request.Builder()
                        .url(RegistrationUrl)
                        .addHeader(HeaderUserTokenKey, userId.toString())
                        .method("POST", jsonRequestBody {
                            name("id").value(rawId)
                            name("type").value(PublicKeyCredentialType.PUBLIC_KEY.toString())
                            name("rawId").value(rawId)
                            name("response").objectValue {
                                name("clientDataJSON").value(
                                        response.clientDataJSON.toBase64()
                                )
                                name("attestationObject").value(
                                        response.attestationObject.toBase64()
                                )
                            }
                        })
                        .build()
        )
        return Tasks.call(executor, {
            val apiResponse = call.execute()
            if (!apiResponse.isSuccessful) {
                throwResponseError(apiResponse, "Error calling registerResponse")
            }
            parseUserCredentials(
                    apiResponse.body ?: throw ApiException("Empty response from registerResponse"))
        })
    }

    fun loginRequest(userId: Long, credentialId: String?,
                     executor: Executor): Task<PublicKeyCredentialRequestOptions> {
        val call = client.newCall(
                Request.Builder()
                        .url(
                                buildString {
                                    append(LoginChallengeUrl)
                                    if (credentialId != null) {
                                        append("?credId=$credentialId")
                                    }
                                }
                        )
                        .addHeader(HeaderUserIdKey, userId.toString())
                        .get()
                        .build()
        )
        return Tasks.call(executor, {
            val response = call.execute()
            if (!response.isSuccessful) {
                throwResponseError(response, "Error calling loginRequest")
            }
            parsePublicKeyCredentialRequestOptions(
                    response.body ?: throw ApiException("Empty response in loginRequest")
            )
        })
    }

    private fun jsonRequestBody(body: JsonWriter.() -> Unit): RequestBody {
        val output = StringWriter()
        JsonWriter(output).use { writer ->
            writer.beginObject()
            writer.body()
            writer.endObject()
        }
        return output.toString().toRequestBody(JSON)
    }

    private fun JsonWriter.objectValue(body: JsonWriter.() -> Unit) {
        beginObject()
        body()
        endObject()
    }

    //================= Parsers ========================== //

    private fun parsePublicKeyCredentialRequestOptions(
            body: ResponseBody
    ): PublicKeyCredentialRequestOptions {
        val builder = PublicKeyCredentialRequestOptions.Builder()
        JsonReader(body.byteStream().bufferedReader()).use { reader ->
            reader.beginObject()
            while (reader.hasNext()) {
                when (reader.nextName()) {
                    "challenge" -> builder.setChallenge(parseChallenge(reader))
                    "userVerification" -> reader.skipValue()
                    "allowCredentials" -> builder.setAllowList(parseCredentialDescriptors(reader))
                    "rpId" -> builder.setRpId(reader.nextString())
                    "timeout" -> builder.setTimeoutSeconds(reader.nextDouble())
                    else -> reader.skipValue()
                }
            }
            reader.endObject()
        }
        return builder.build()
    }

    fun parsePublicKeyCredentialCreationOptions(
            body: ResponseBody
    ): PublicKeyCredentialCreationOptions {
        val builder = PublicKeyCredentialCreationOptions.Builder()
        JsonReader(body.byteStream().bufferedReader()).use { reader ->
            reader.beginObject()
            while (reader.hasNext()) {
                when (reader.nextName()) {
                    "user" -> builder.setUser(parseUser(reader))
                    "challenge" -> builder.setChallenge(parseChallenge(reader))
                    "pubKeyCredParams" -> builder.setParameters(parseParameters(reader))
                    "timeout" -> builder.setTimeoutSeconds(reader.nextDouble())
                    "attestation" -> reader.skipValue() // Unused
                    "excludeCredentials" -> builder.setExcludeList(
                            parseCredentialDescriptors(reader)
                    )
                    "authenticatorSelection" -> builder.setAuthenticatorSelection(
                            parseSelection(reader)
                    )
                    "rp" -> builder.setRp(parseRp(reader))
                    else -> reader.skipValue()
                }
            }
            reader.endObject()
        }
        return builder.build()
    }


    private fun parseChallenge(reader: JsonReader): ByteArray {
        var value: String? = null
        reader.beginObject()
        while (reader.hasNext()) {
            when (reader.nextName()) {
                "value" -> value = reader.nextString()
                else -> reader.skipValue()
            }
        }
        reader.endObject()
        return value?.decodeBase64()!!.toByteArray()
    }

    private fun parseRp(reader: JsonReader): PublicKeyCredentialRpEntity {
        var id: String? = null
        var name: String? = null
        reader.beginObject()
        while (reader.hasNext()) {
            when (reader.nextName()) {
                "id" -> id = reader.nextString()
                "name" -> name = reader.nextString()
                else -> reader.skipValue()
            }
        }
        reader.endObject()
        return PublicKeyCredentialRpEntity(id!!, name!!, /* icon */ null)
    }

    private fun parseSelection(reader: JsonReader): AuthenticatorSelectionCriteria {
        val builder = AuthenticatorSelectionCriteria.Builder()
        reader.beginObject()
        while (reader.hasNext()) {
            when (reader.nextName()) {
                "authenticatorAttachment" -> builder.setAttachment(
                        Attachment.fromString(reader.nextString())
                )
                "userVerification" -> reader.skipValue()
                else -> reader.skipValue()
            }
        }
        reader.endObject()
        return builder.build()
    }

    private fun parseCredentialDescriptors(
            reader: JsonReader
    ): List<PublicKeyCredentialDescriptor> {
        val list = mutableListOf<PublicKeyCredentialDescriptor>()
        reader.beginArray()
        while (reader.hasNext()) {
            var id: String? = null
            reader.beginObject()
            while (reader.hasNext()) {
                when (reader.nextName()) {
                    "id" -> id = reader.nextString()
                    "type" -> reader.skipValue()
                    "transports" -> reader.skipValue()
                    else -> reader.skipValue()
                }
            }
            reader.endObject()
            list.add(
                    PublicKeyCredentialDescriptor(
                            PublicKeyCredentialType.PUBLIC_KEY.toString(),
                            id!!.decodeBase64()!!.toByteArray(),
                            /* transports */ null
                    )
            )
        }
        reader.endArray()
        return list
    }

    private fun parseUser(reader: JsonReader): PublicKeyCredentialUserEntity {
        reader.beginObject()
        var id: String? = null
        var name: String? = null
        var displayName = ""
        while (reader.hasNext()) {
            when (reader.nextName()) {
                "id" -> id = reader.nextString()
                "name" -> name = reader.nextString()
                "displayName" -> displayName = reader.nextString()
                else -> reader.skipValue()
            }
        }
        reader.endObject()
        return PublicKeyCredentialUserEntity(
                id!!.decodeBase64()!!.toByteArray(),
                name!!,
                null, // icon
                displayName
        )
    }

    private fun parseParameters(reader: JsonReader): List<PublicKeyCredentialParameters> {
        val parameters = mutableListOf<PublicKeyCredentialParameters>()
        reader.beginArray()
        while (reader.hasNext()) {
            reader.beginObject()
            var type: String? = null
            var alg = 0
            while (reader.hasNext()) {
                when (reader.nextName()) {
                    "type" -> type = reader.nextString()
                    "alg" -> alg = reader.nextInt()
                    else -> reader.skipValue()
                }
            }
            reader.endObject()
            parameters.add(PublicKeyCredentialParameters(type!!, alg))
        }
        reader.endArray()
        return parameters
    }

    private fun parseUserCredentials(body: ResponseBody): List<Credential> {
        fun readCredentials(reader: JsonReader): List<Credential> {
            val credentials = mutableListOf<Credential>()
            reader.beginArray()
            while (reader.hasNext()) {
                reader.beginObject()
                var id: String? = null
                while (reader.hasNext()) {
                    when (reader.nextName()) {
                        "credId" -> id = reader.nextString()
                        else -> reader.skipValue()
                    }
                }
                reader.endObject()
                if (id != null) {
                    credentials.add(Credential(id))
                }
            }
            reader.endArray()
            return credentials
        }
        JsonReader(body.byteStream().bufferedReader()).use { reader ->
            reader.beginObject()
            while (reader.hasNext()) {
                val name = reader.nextName()
                if (name == "credentials") {
                    return readCredentials(reader)
                } else {
                    reader.skipValue()
                }
            }
            reader.endObject()
        }
        throw ApiException("Cannot parse credentials")
    }

    private fun parseError(body: ResponseBody): String {
        val errorString = body.string()
        try {
            JsonReader(StringReader(errorString)).use { reader ->
                reader.beginObject()
                while (reader.hasNext()) {
                    val name = reader.nextName()
                    if (name == "error") {
                        val token = reader.peek()
                        if (token == JsonToken.STRING) {
                            return reader.nextString()
                        }
                        return "Unknown"
                    } else {
                        reader.skipValue()
                    }
                }
                reader.endObject()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Cannot parse the error: $errorString", e)
            // Don't throw; this method is called during throwing.
        }
        return ""
    }

    private fun throwResponseError(response: Response, message: String): Nothing {
        val b = response.body
        if (b != null) {
            throw ApiException("$message; ${parseError(b)}")
        } else {
            throw ApiException(message)
        }
    }
}