
// central.c - communication with central server

#include "qwsvdef.h"
#include <curl/curl.h>

#define GENERATE_CHALLENGE_PATH     "Authentication/GenerateChallenge"
#define VERIFY_RESPONSE_PATH        "Authentication/VerifyResponse"
#define CHECKIN_PATH                "ServerApi/Checkin"
#define MIN_CHECKIN_PERIOD          60

#ifdef _WIN32
#pragma comment(lib, "libcurld.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wldap32.lib")
#endif

static cvar_t sv_www_address = { "sv_www_address", "" };
static cvar_t sv_www_authkey = { "sv_www_authkey", "" };
static cvar_t sv_www_checkin_period = { "sv_www_checkin_period", "60" };

static CURLM* curl_handle = NULL;

static double last_checkin_time;

#define MAX_RESPONSE_LENGTH    (4096*2)

struct web_request_data_s;

typedef void(*web_response_func_t)(struct web_request_data_s* req, qbool valid);
static void Web_ConstructURL(char* url, const char* path, int sizeof_url);
static int utf_encode_string(char* value, char* encoded_value);
static struct web_request_data_s* Web_CreateRequest(web_response_func_t callback, const char* requestId, void* internal_data);
static void Web_FreeRequest(struct web_request_data_s* data);
static qbool Web_AddFormPart(struct web_request_data_s* data, const char* name, const char* value, qbool file);
static void Web_SubmitRequestForm(const char* url, struct web_request_data_s* data);

typedef struct web_request_data_s {
	CURL*               handle;
	double              time_sent;

	// response from server
	char                response[MAX_RESPONSE_LENGTH];
	size_t              response_length;

	// form data
	curl_mime*          form;

	// called when response complete
	web_response_func_t onCompleteCallback;
	void*               internal_data;
	char*               request_id;                 // if set, content will be passed to game-mod. will be Q_free()'d

	struct web_request_data_s* next;
} web_request_data_t;

static int utf8Encode(char in, char* out1, char* out2) {
	if (in <= 0x7F) {
		// <= 127 is encoded as single byte, no translation
		*out1 = in;
		return 1;
	}
	else {
		// Two byte characters... 5 bits then 6
		*out1 = 0xC0 | ((in >> 6) & 0x1F);
		*out2 = 0x80 | (in & 0x3F);
		return 2;
	}
}

static web_request_data_t* web_requests;

static qbool CheckFileExists(const char* path)
{
	FILE* f;
	if (!(f = fopen(path, "rb"))) {
		return false;
	}
	fclose(f);
	return true;
}

size_t Web_StandardTokenWrite(void* buffer, size_t size, size_t nmemb, void* userp)
{
	web_request_data_t* data = (web_request_data_t*)userp;
	size_t available = sizeof(data->response) - 1 - data->response_length;
	if (size * nmemb > available) {
		Con_DPrintf("WWW: Response too large, size*nmemb = %d, available %d\n", size * nmemb, available);
		return 0;
	}
	else if (size * nmemb > 0) {
		Con_DPrintf("WWW: response received, writing %d bytes\n", size * nmemb);
		memcpy(data->response + data->response_length, buffer, size * nmemb);
		data->response_length += size * nmemb;
		Con_DPrintf("WWW: response_length now %d bytes\n", data->response_length);
	}
	return size * nmemb;
}

typedef struct response_field_s {
	const char* name;
	const char** value;
} response_field_t;

static int ProcessWebResponse(web_request_data_t* req, response_field_t* fields, int field_count)
{
	char* colon, *newline;
	char* start = req->response;
	int i;
	int total_fields = 0;

	// Response should be multiple lines, <Key>:<Value>\n
	// For multi-line values, prefix end of line with $
	req->response[req->response_length] = '\0';
	while ((colon = strchr(start, ':'))) {
		newline = strchr(colon, '\n');
		if (newline) {
			while (newline && newline != colon + 1 && *(newline - 1) == '$') {
				*(newline - 1) = ' ';
				newline = strchr(newline + 1, '\n');
			}
			if (newline) {
				*newline = '\0';
			}
		}

		*colon = '\0';
		for (i = 0; i < field_count; ++i) {
			if (!strcmp(start, fields[i].name)) {
				*fields[i].value = colon + 1;
			}
		}

		if (newline == NULL) {
			break;
		}

		start = newline + 1;
		while (*start && (*start == 10 || *start == 13)) {
			++start;
		}
		++total_fields;
	}

	return total_fields;
}

void Auth_GenerateChallengeResponse(web_request_data_t* req, qbool valid)
{
	client_t* client = (client_t*) req->internal_data;
	const char* response = NULL;
	const char* challenge = NULL;
	const char* message = NULL;
	response_field_t fields[] = {
		{ "Result", &response },
		{ "Challenge", &challenge },
		{ "Message", &message }
	};

	if (client->login_request_time != req->time_sent) {
		// Ignore result, subsequent request sent
		return;
	}

	req->internal_data = NULL;
	ProcessWebResponse(req, fields, sizeof(fields) / sizeof(fields[0]));

	if (response && !strcmp(response, "Success") && challenge) {
		char buffer[128];
		strlcpy(buffer, "//challenge ", sizeof(buffer));
		strlcat(buffer, challenge, sizeof(buffer));
		strlcat(buffer, "\n", sizeof(buffer));

		strlcpy(client->login_challenge, challenge, sizeof(client->login_challenge));
		SV_ClientPrintf2(client, PRINT_HIGH, "Challenge stored...\n", message);

		ClientReliableWrite_Begin (client, svc_stufftext, 2+strlen(buffer));
		ClientReliableWrite_String (client, buffer);
	}
	else if (message) {
		SV_ClientPrintf2(client, PRINT_HIGH, "Error: %s\n", message);
	}
	else {
		// Maybe add CURLOPT_ERRORBUFFER?
		SV_ClientPrintf2(client, PRINT_HIGH, "Error: unknown error\n");
	}
}

void Auth_ProcessLoginAttempt(web_request_data_t* req, qbool valid)
{
	client_t* client = (client_t*) req->internal_data;
	const char* response = NULL;
	const char* login = NULL;
	const char* preferred_alias = NULL;
	const char* message = NULL;
	const char* flag = NULL;
	const char* confirmation = NULL;
	response_field_t fields[] = {
		{ "Result", &response },
		{ "Alias", &preferred_alias },
		{ "Login", &login },
		{ "Message", &message },
		{ "Flag", &flag },
		{ "Confirmation", &confirmation }
	};

	req->internal_data = NULL;
	if (client->login_request_time != req->time_sent) {
		// Ignore result, subsequent request sent
		return;
	}

	ProcessWebResponse(req, fields, sizeof(fields) / sizeof(fields[0]));

	if (response && !strcmp(response, "Success")) {
		if (login) {
			char oldval[MAX_EXT_INFO_STRING];

			strlcpy(oldval, Info_Get(&client->_userinfo_ctx_, "*auth"), sizeof(oldval));
			strlcpy(client->login, login, sizeof(client->login));

			Info_SetStar(&client->_userinfo_ctx_, "*auth", login);
			ProcessUserInfoChange(client, "*auth", oldval);
		}

		if (confirmation) {
			strlcpy(client->login_confirmation, confirmation, sizeof(client->login_confirmation));
		}

		{
			char oldval[MAX_EXT_INFO_STRING];

			flag = (flag ? flag : "");
			strlcpy(oldval, Info_Get(&client->_userinfo_ctx_, "*flag"), sizeof(oldval));
			strlcpy(client->login_flag, flag, sizeof(client->login_flag));
			Info_SetStar(&client->_userinfo_ctx_, "*flag", flag);
			ProcessUserInfoChange(client, "*flag", oldval);
		}

		preferred_alias = preferred_alias ? preferred_alias : login;
		if (preferred_alias) {
			strlcpy(client->login_alias, preferred_alias, sizeof(client->login_alias));
		}
		client->logged_in_via_web = true;

		SV_LoginWebCheck(client);
	}
	else if (message) {
		SV_ClientPrintf2(client, PRINT_HIGH, "Error: %s\n", message);
		SV_LoginWebFailed(client);
	}
	else {
		// Maybe add CURLOPT_ERRORBUFFER?
		SV_ClientPrintf2(client, PRINT_HIGH, "Error: unknown error (invalid response from server)\n");
		SV_LoginWebFailed(client);
	}
}

void Web_PostResponse(web_request_data_t* req, qbool valid)
{
	if (valid) {
		const char* broadcast = NULL;
		const char* upload = NULL;
		const char* uploadPath = NULL;

		response_field_t fields[] = {
			{ "Broadcast", &broadcast },
			{ "UploadPath", &uploadPath },
			{ "Upload", &upload }
		};

		req->response[req->response_length] = '\0';

		Con_DPrintf("Response from web server:\n");
		Con_DPrintf(req->response);

		ProcessWebResponse(req, fields, sizeof(fields) / sizeof(fields[0]));

		if (broadcast) {
			// Server is making announcement
			SV_BroadcastPrintfEx(PRINT_HIGH, 0, "%s\n", broadcast);
		}
		if (upload && uploadPath) {
			if (strstr(uploadPath, "//") || FS_UnsafeFilename(upload)) {
				Con_Printf("Upload request deemed unsafe, ignoring...\n");
			}
			else {
				if (!strncmp(upload, "demos/", 6)) {
					// Ok - could be demo_dir, or full path
					char demoName[MAX_OSPATH];

					if (sv_demoDir.string[0]) {
						char url[512];
						qbool found;

						found = FS_FormatPath(demoName, sizeof(demoName), "%s/%s/%s", fs_gamedir, sv_demoDir.string, upload + 6) && CheckFileExists(demoName);
						if (!found && sv_demoDirAlt.string[0]) {
							found = FS_FormatPath(demoName, sizeof(demoName), "%s/%s/%s", fs_gamedir, sv_demoDirAlt.string, upload + 6) && CheckFileExists(demoName);
						}

						if (found) {
							web_request_data_t* data = Web_CreateRequest(Web_PostResponse, "upload", NULL);

							if (data) {
								if (Web_AddFormPart(data, "file", demoName, true) &&
									Web_AddFormPart(data, "localPath", upload, false)) {
									Web_ConstructURL(url, uploadPath, sizeof(url));
									Con_Printf("Uploading %s...\n", demoName);
									Web_SubmitRequestForm(url, data);
								}
								else {
									Web_FreeRequest(data);
								}
							}
						}
						else {
							Con_Printf("Couldn't find requested demo, ignoring...\n");
						}
					}
				}
				else {
					Con_Printf("Upload request folder not authorised, ignoring...\n");
				}
			}
		}
	}
	else {
		Con_Printf("Failure contacting central server.\n");
	}

	if (req->internal_data) {
		Q_free(req->internal_data);
	}
}

static void Web_FreeRequest(web_request_data_t* data)
{
	curl_easy_cleanup(data->handle);
	curl_mime_free(data->form);
	Q_free(data->request_id);
	Q_free(data);
}

static web_request_data_t* Web_CreateRequest(web_response_func_t callback, const char* requestId, void* internal_data)
{
	web_request_data_t* data = Q_calloc(1, sizeof(*data));

	data->handle = curl_easy_init();
	if (data->handle)
		data->form = curl_mime_init(data->handle);
	if (!data->handle || !data->form) {
		Con_Printf("Request failed (initializing form)\n");
		Web_FreeRequest(data);
		return NULL;
	}

	data->onCompleteCallback = callback;
	data->time_sent = curtime;
	data->internal_data = internal_data;
	data->request_id = requestId && requestId[0] ? Q_strdup(requestId) : NULL;
	return data;
}

static qbool Web_AddFormPart(web_request_data_t* data, const char* name, const char* value, qbool file)
{
	curl_mimepart* part = curl_mime_addpart(data->form);
	CURLcode code = part ? curl_mime_name(part, name) : CURLE_OUT_OF_MEMORY;

	if (code == CURLE_OK)
		code = file ? curl_mime_filedata(part, value) : curl_mime_data(part, value, CURL_ZERO_TERMINATED);
	if (code != CURLE_OK) {
		Con_Printf("Request failed (adding to form): %s\n", curl_easy_strerror(code));
		return false;
	}
	return true;
}

// Takes ownership of data, including on submission failure.
static void Web_SubmitRequestForm(const char* url, web_request_data_t* data)
{
	CURLcode code;
	CURLMcode multi_code;

	if (!Web_AddFormPart(data, "authKey", sv_www_authkey.string, false))
		goto failed;

	code = curl_easy_setopt(data->handle, CURLOPT_URL, url);
	if (code == CURLE_OK)
		code = curl_easy_setopt(data->handle, CURLOPT_WRITEDATA, data);
	if (code == CURLE_OK)
		code = curl_easy_setopt(data->handle, CURLOPT_WRITEFUNCTION, Web_StandardTokenWrite);
	if (code == CURLE_OK)
		code = curl_easy_setopt(data->handle, CURLOPT_MIMEPOST, data->form);
	if (code != CURLE_OK) {
		Con_Printf("Request failed (setting options): %s\n", curl_easy_strerror(code));
		goto failed;
	}

	multi_code = curl_multi_add_handle(curl_handle, data->handle);
	if (multi_code != CURLM_OK) {
		Con_Printf("Request failed (submitting): %s\n", curl_multi_strerror(multi_code));
		goto failed;
	}

	data->next = web_requests;
	web_requests = data;
	return;

failed:
	if (data->onCompleteCallback)
		data->onCompleteCallback(data, false);
	Web_FreeRequest(data);
}

void Central_VerifyChallengeResponse(client_t* client, const char* challenge, const char* response)
{
	char url[512];
	web_request_data_t* data;

	if (!sv_www_address.string[0]) {
		SV_ClientPrintf2(client, PRINT_HIGH, "Remote logins not supported on this server\n");
		return;
	}

	data = Web_CreateRequest(Auth_ProcessLoginAttempt, NULL, client);
	if (!data)
		return;
	if (!Web_AddFormPart(data, "challenge", challenge, false) ||
		!Web_AddFormPart(data, "response", response, false)) {
		Web_FreeRequest(data);
		return;
	}

	Web_ConstructURL(url, VERIFY_RESPONSE_PATH, sizeof(url));
	client->login_request_time = curtime;
	Web_SubmitRequestForm(url, data);
}

void Central_GenerateChallenge(client_t* client, const char* username, qbool during_login)
{
	char url[512];
	web_request_data_t* data;

	if (!sv_www_address.string[0]) {
		SV_ClientPrintf2(client, PRINT_HIGH, "Remote logins not supported on this server\n");
		return;
	}

	data = Web_CreateRequest(Auth_GenerateChallengeResponse, NULL, client);
	if (!data)
		return;
	if (!Web_AddFormPart(data, "userName", username, false) ||
		!Web_AddFormPart(data, "status", during_login ? "0" : "1", false)) {
		Web_FreeRequest(data);
		return;
	}

	Web_ConstructURL(url, GENERATE_CHALLENGE_PATH, sizeof(url));
	client->login_request_time = curtime;
	Web_SubmitRequestForm(url, data);
}

static void Web_ConstructURL(char* url, const char* path, int sizeof_url)
{
	strlcpy(url, sv_www_address.string, sizeof_url);
	if (!url[0] || url[strlen(url) - 1] != '/') {
		strlcat(url, "/", sizeof_url);
	}
	while (*path == '/') {
		++path;
	}
	strlcat(url, path, sizeof_url);
}

#define MAX_ENCODED_STRINGLEN 128

static qbool Web_AddParametersToRequest(int first_param, web_request_data_t* data)
{
	int i;

	for (i = first_param; i < Cmd_Argc() - 1; i += 2) {
		char encoded_value[MAX_ENCODED_STRINGLEN];
		int j;
		char* name;
		char* value;

		name = Cmd_Argv(i);
		value = Cmd_Argv(i + 1);
		if (!strcmp(name, "*internal")) {
			if (!strcmp(value, "authinfo")) {
				int login_count = 0;

				// Also submit authentication challenges/responses
				for (j = 0; j < MAX_CLIENTS; ++j) {
					if (svs.clients[j].state > cs_free) {
						if (svs.clients[j].login[0] && svs.clients[j].logged_in_via_web) {
							name = va("logins[%d].name", login_count);
							utf_encode_string(svs.clients[j].login, encoded_value);
							if (!Web_AddFormPart(data, name, encoded_value, false))
								return false;

							name = va("logins[%d].token", login_count);
							utf_encode_string(svs.clients[j].login_confirmation, encoded_value);
							if (!Web_AddFormPart(data, name, encoded_value, false))
								return false;

							++login_count;
						}
					}
				}

				snprintf(encoded_value, sizeof(encoded_value), "%d", login_count);
				if (!Web_AddFormPart(data, "logincount", encoded_value, false))
					return false;
			}
			continue;
		}
		else {
			utf_encode_string(value, encoded_value);
		}

		if (!Web_AddFormPart(data, name, encoded_value, false))
			return false;
	}

	return true;
}

static void Web_SendRequest(qbool post)
{
	web_request_data_t* data;
	char url[512];

	if (!sv_www_address.string[0]) {
		Con_Printf("Address not set - functionality disabled\n");
		return;
	}

	if (Cmd_Argc() < 3) {
		Con_Printf("Usage: %s <url> <request-id> (<key> <value>)*\n", Cmd_Argv(0));
		return;
	}

	Web_ConstructURL(url, Cmd_Argv(1), sizeof(url));
	data = Web_CreateRequest(Web_PostResponse, Cmd_Argv(2), NULL);
	if (!data)
		return;
	if (!Web_AddParametersToRequest(3, data)) {
		Web_FreeRequest(data);
		return;
	}

	Web_SubmitRequestForm(url, data);
}

int utf_encode_string(char* value, char* encoded_value)
{
	int j;
	int encoded_length = 0;
	for (j = 0; j < strlen(value) && encoded_length < MAX_ENCODED_STRINGLEN - 2; ++j) {
		encoded_length += utf8Encode(value[j], &encoded_value[encoded_length], &encoded_value[encoded_length + 1]);
	}
	encoded_value[encoded_length] = '\0';
	return encoded_length;
}

static void Web_GetRequest_f(void)
{
	Web_SendRequest(false);
}

static void Web_PostRequest_f(void)
{
	Web_SendRequest(true);
}

static void Web_PostFileRequest_f(void)
{
	web_request_data_t* data;
	char url[512];
	char path[MAX_OSPATH];
	char demo_path[MAX_OSPATH];
	const char* filename;

	if (!sv_www_address.string[0]) {
		Con_Printf("Address not set - functionality disabled\n");
		return;
	}

	if (Cmd_Argc() < 4) {
		Con_Printf("Usage: %s <url> <request-id> <file> (<key> <value>)*\n", Cmd_Argv(0));
		return;
	}

	filename = Cmd_Argv(3);
	if (filename[0] == '*' && filename[1] == '\0') {
		const char* demoname = SV_MVDDemoName();
		const char* sidecar;

		if (!sv.mvdrecording || !demoname) {
			Con_Printf("Not recording demo!\n");
			return;
		}

		sidecar = SV_MVDName2Txt(demoname);
		if (!sidecar) {
			Con_Printf("Filename invalid\n");
			return;
		}

		// The recorder appends the configured directory even if it starts with a slash.
		if (!FS_FormatPath(demo_path, sizeof(demo_path), "%s/%s", sv_demoDir.string, sidecar))
			return;
		if (strstr(demo_path, "..") || FS_HasAmbiguousWindowsPath(demo_path)) {
			Con_Printf("Filename invalid\n");
			return;
		}

		filename = demo_path;
	} else if (FS_UnsafeFilename(filename) || FS_HasAmbiguousWindowsPath(filename)
		|| strstr(filename, ".cfg")
		|| !strcasecmp(COM_FileExtension(filename), "cfg")) {
		Con_Printf("Filename invalid\n");
		return;
	}

	if (!FS_FormatPath(path, sizeof(path), "%s/%s", fs_gamedir, filename)) {
		return;
	}

	Web_ConstructURL(url, Cmd_Argv(1), sizeof(url));

	if (! CheckFileExists(path)) {
		Con_Printf("Failed to open file\n");
		return;
	}

	data = Web_CreateRequest(Web_PostResponse, Cmd_Argv(2), NULL);
	if (!data)
		return;
	if (!Web_AddFormPart(data, "file", path, true) ||
		!Web_AddParametersToRequest(4, data)) {
		Web_FreeRequest(data);
		return;
	}

	Web_SubmitRequestForm(url, data);
}

void Central_ProcessResponses(void)
{
	CURLMsg* msg;
	int running_handles = 0;
	int messages_in_queue = 0;
	qbool server_busy = false;

	if (!last_checkin_time) {
		last_checkin_time = curtime;
		return;
	}

	curl_multi_perform(curl_handle, &running_handles);

	server_busy = running_handles || GameStarted();

	while ((msg = curl_multi_info_read(curl_handle, &messages_in_queue))) {
		if (msg->msg == CURLMSG_DONE) {
			CURL* handle = msg->easy_handle;
			CURLcode result = msg->data.result;
			web_request_data_t** list_pointer = &web_requests;

			curl_multi_remove_handle(curl_handle, handle);

			while (*list_pointer) {
				web_request_data_t* this = *list_pointer;

				if (this->handle == handle) {
					// Remove from queue immediately
					*list_pointer = this->next;

					if (this->onCompleteCallback) {
						if (result == CURLE_OK) {
							this->onCompleteCallback(this, true);
						}
						else {
							Con_DPrintf("ERROR: %s\n", curl_easy_strerror(result));
							this->onCompleteCallback(this, false);
						}
					}
					else {
						if (result != CURLE_OK) {
							Con_DPrintf("ERROR: %s\n", curl_easy_strerror(result));
						}
						else {
							Con_DPrintf("WEB OK, no callback\n");
						}
					}

					// free memory
					Web_FreeRequest(this);

					break;
				}

				list_pointer = &this->next;
			}

		}
	}

	if (sv_www_address.string[0] && !server_busy && curtime - last_checkin_time > max(MIN_CHECKIN_PERIOD, sv_www_checkin_period.value)) {
		char url[512];

		Web_ConstructURL(url, CHECKIN_PATH, sizeof(url));

		{
			web_request_data_t* data = Web_CreateRequest(Web_PostResponse, NULL, NULL);
			if (data)
				Web_SubmitRequestForm(url, data);
		}

		last_checkin_time = curtime;
	}
	else if (server_busy) {
		last_checkin_time = curtime;
	}
}

void Central_Shutdown(void)
{
	if (curl_handle) {
		while (web_requests) {
			web_request_data_t* data = web_requests;
			web_requests = data->next;
			curl_multi_remove_handle(curl_handle, data->handle);
			Web_FreeRequest(data);
		}
		curl_multi_cleanup(curl_handle);
		curl_handle = NULL;
	}

	curl_global_cleanup();
}

void Central_Init(void)
{
	curl_global_init(CURL_GLOBAL_DEFAULT);

	Cvar_Register(&sv_www_address);
	Cvar_Register(&sv_www_authkey);
	Cvar_Register(&sv_www_checkin_period);

	curl_handle = curl_multi_init();

	if (curl_handle) {
		Cmd_AddCommand("sv_web_get", Web_GetRequest_f);
		Cmd_AddCommand("sv_web_post", Web_PostRequest_f);
		Cmd_AddCommand("sv_web_postfile", Web_PostFileRequest_f);
	}
}
