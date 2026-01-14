#include "log.h"
#include "misc.h"

const char* GetLanguageName(LANGID langID) {
    switch (langID) {
        case 0x0436: return "Afrikaans (South Africa)";
        case 0x041c: return "Albanian (Albania)";
        case 0x0401: return "Arabic (Saudi Arabia)";
        case 0x0801: return "Arabic (Iraq)";
        case 0x0c01: return "Arabic (Egypt)";
        case 0x1001: return "Arabic (Libya)";
        case 0x1401: return "Arabic (Algeria)";
        case 0x1801: return "Arabic (Morocco)";
        case 0x1c01: return "Arabic (Tunisia)";
        case 0x2001: return "Arabic (Oman)";
        case 0x2401: return "Arabic (Yemen)";
        case 0x2801: return "Arabic (Syria)";
        case 0x2c01: return "Arabic (Jordan)";
        case 0x3001: return "Arabic (Lebanon)";
        case 0x3401: return "Arabic (Kuwait)";
        case 0x3801: return "Arabic (U.A.E.)";
        case 0x3c01: return "Arabic (Bahrain)";
        case 0x4001: return "Arabic (Qatar)";
        case 0x042b: return "Armenian (Armenia)";
        case 0x044d: return "Assamese";
        case 0x042c: return "Azeri (Latin)";
        case 0x082c: return "Azeri (Cyrillic)";
        case 0x042d: return "Basque";
        case 0x0423: return "Belarusian";
        case 0x0445: return "Bengali (India)";
        case 0x201a: return "Bosnian (Bosnia and Herzegovina)";
        case 0x0402: return "Bulgarian";
        case 0x0455: return "Burmese";
        case 0x0403: return "Catalan";
        case 0x0c04: return "Chinese (Hong Kong SAR)";
        case 0x1404: return "Chinese (Macao SAR)";
        case 0x0804: return "Chinese (PRC)";
        case 0x1004: return "Chinese (Singapore)";
        case 0x0404: return "Chinese (Taiwan)";
        case 0x041a: return "Croatian";
        case 0x101a: return "Croatian (Bosnia and Herzegovina)";
        case 0x0405: return "Czech";
        case 0x0406: return "Danish";
        case 0x0465: return "Divehi";
        case 0x0413: return "Dutch (Netherlands)";
        case 0x0813: return "Dutch (Belgium)";
        case 0x0409: return "English (United States)";
        case 0x0809: return "English (United Kingdom)";
        case 0x0c09: return "English (Australia)";
        case 0x1009: return "English (Canada)";
        case 0x1409: return "English (New Zealand)";
        case 0x1809: return "English (Ireland)";
        case 0x1c09: return "English (South Africa)";
        case 0x2009: return "English (Jamaica)";
        case 0x2409: return "English (Caribbean)";
        case 0x2809: return "English (Belize)";
        case 0x2c09: return "English (Trinidad)";
        case 0x3009: return "English (Zimbabwe)";
        case 0x3409: return "English (Philippines)";
        case 0x0425: return "Estonian";
        case 0x0438: return "Faeroese";
        case 0x0429: return "Farsi";
        case 0x040b: return "Finnish";
        case 0x040c: return "French (France)";
        case 0x080c: return "French (Belgium)";
        case 0x0c0c: return "French (Canada)";
        case 0x100c: return "French (Switzerland)";
        case 0x140c: return "French (Luxembourg)";
        case 0x180c: return "French (Monaco)";
        case 0x0456: return "Galician";
        case 0x0437: return "Georgian";
        case 0x0407: return "German (Germany)";
        case 0x0807: return "German (Switzerland)";
        case 0x0c07: return "German (Austria)";
        case 0x1007: return "German (Luxembourg)";
        case 0x1407: return "German (Liechtenstein)";
        case 0x0408: return "Greek";
        case 0x0447: return "Gujarati";
        case 0x040d: return "Hebrew";
        case 0x0439: return "Hindi";
        case 0x040e: return "Hungarian";
        case 0x040f: return "Icelandic";
        case 0x0421: return "Indonesian";
        case 0x045d: return "Inuktitut";
        case 0x0434: return "isiXhosa";
        case 0x0435: return "isiZulu";
        case 0x0410: return "Italian (Italy)";
        case 0x0810: return "Italian (Switzerland)";
        case 0x0411: return "Japanese";
        case 0x044b: return "Kannada";
        case 0x0453: return "Khmer";
        case 0x0486: return "K'iche'";
        case 0x0412: return "Korean";
        case 0x0457: return "Konkani";
        case 0x0414: return "Norwegian (Bokmål)";
        case 0x0814: return "Norwegian (Nynorsk)";
        case 0x0415: return "Polish";
        case 0x0416: return "Portuguese (Brazil)";
        case 0x0816: return "Portuguese (Portugal)";
        case 0x0417: return "Raeto-Romance";
        case 0x0418: return "Romanian";
        case 0x0419: return "Russian";
        case 0x0432: return "Sesotho sa Leboa";
        case 0x0433: return "Setswana";
        case 0x041b: return "Slovak";
        case 0x0424: return "Slovenian";
        case 0x040a: return "Spanish (Traditional Sort)";
        case 0x080a: return "Spanish (Mexico)";
        case 0x0c0a: return "Spanish (Spain)";
        case 0x100a: return "Spanish (Guatemala)";
        case 0x140a: return "Spanish (Costa Rica)";
        case 0x180a: return "Spanish (Panama)";
        case 0x1c0a: return "Spanish (Dominican Republic)";
        case 0x200a: return "Spanish (Venezuela)";
        case 0x240a: return "Spanish (Colombia)";
        case 0x280a: return "Spanish (Peru)";
        case 0x2c0a: return "Spanish (Argentina)";
        case 0x300a: return "Spanish (Ecuador)";
        case 0x340a: return "Spanish (Chile)";
        case 0x380a: return "Spanish (Uruguay)";
        case 0x3c0a: return "Spanish (Paraguay)";
        case 0x400a: return "Spanish (Bolivia)";
        case 0x440a: return "Spanish (El Salvador)";
        case 0x480a: return "Spanish (Honduras)";
        case 0x4c0a: return "Spanish (Nicaragua)";
        case 0x500a: return "Spanish (Puerto Rico)";
        case 0x0430: return "Sutu";
        case 0x0441: return "Swahili";
        case 0x041d: return "Swedish";
        case 0x081d: return "Swedish (Finland)";
        case 0x045a: return "Syriac";
        case 0x041e: return "Thai";
        case 0x0451: return "Sindhi (India)";
        case 0x041f: return "Turkish";
        case 0x0422: return "Ukrainian";
        case 0x0420: return "Urdu (Pakistan)";
        case 0x0820: return "Urdu (India)";
        case 0x0443: return "Uzbek (Latin)";
        case 0x0843: return "Uzbek (Cyrillic)";
        case 0x042a: return "Vietnamese";
        default: return "Unknown Language";
    }
}

HOOKDEF(int, WINAPI, GetUserDefaultLCID,
	void
) {
	const char* LanguageName = NULL;
	int ret = Old_GetUserDefaultLCID();
	if (g_config.lang)
		ret = g_config.lang;
	if (ret)
		LanguageName = GetLanguageName(ret);
	if (LanguageName)
		LOQ_nonzero("system", "hs", "SystemDefaultLangID", ret, "LanguageName", LanguageName);
	else
		LOQ_nonzero("system", "h", "UserDefaultLCID", ret);
	return ret;
}

HOOKDEF(int, WINAPI, GetSystemDefaultLangID,
	void
) {
	const char* LanguageName = NULL;
	int ret = Old_GetSystemDefaultLangID();
	if (g_config.lang)
		ret = g_config.lang;
	if (ret)
		LanguageName = GetLanguageName(ret);
	if (LanguageName)
		LOQ_nonzero("system", "hs", "SystemDefaultLangID", ret, "LanguageName", LanguageName);
	else
		LOQ_nonzero("system", "h", "SystemDefaultLangID", ret);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtQueryDefaultUILanguage,
	__out	LANGID *DefaultUILanguageId
) {
	const char* LanguageName = NULL;
	NTSTATUS ret = Old_NtQueryDefaultUILanguage(DefaultUILanguageId);
	if (g_config.lang && DefaultUILanguageId)
		*DefaultUILanguageId = (LANGID)g_config.lang;
	if NT_SUCCESS(ret)
		LanguageName = GetLanguageName(*DefaultUILanguageId);
	if (LanguageName)
		LOQ_ntstatus("system", "hs", "DefaultUILanguageId", DefaultUILanguageId, "LanguageName", LanguageName);
	else
		LOQ_ntstatus("system", "h", "DefaultUILanguageId", DefaultUILanguageId);
	return ret;
}

HOOKDEF(NTSTATUS, WINAPI, NtQueryInstallUILanguage,
	__out	LANGID *InstallUILanguageId
) {
	const char* LanguageName = NULL;
	NTSTATUS ret = Old_NtQueryInstallUILanguage(InstallUILanguageId);
	if (g_config.lang && InstallUILanguageId)
		*InstallUILanguageId = (LANGID)g_config.lang;
	if NT_SUCCESS(ret)
		LanguageName = GetLanguageName(*InstallUILanguageId);
	if (LanguageName)
		LOQ_ntstatus("system", "hs", "InstallUILanguageId", InstallUILanguageId, "LanguageName", LanguageName);
	else
		LOQ_ntstatus("system", "h", "InstallUILanguageId", InstallUILanguageId);
	return ret;
}
