// Optional defaults that are built into the app for every phone.
// The APK workflow on GitHub fills these from your repository secrets (FIREBASE_API_KEY, GROQ_API_KEY).
// Leave empty to let each user type them in Settings instead.
window.MB_CONFIG = {
  firebaseApiKey: "",          // Firebase > Project settings > General > Web API key (a public id, not a secret)
  groqApiKey: "",              // optional: online AI answers (anyone who unpacks the APK can read this one)
  groqModel: "",               // empty = pick automatically from your Groq account
  ollamaUrl: "",               // e.g. "http://192.168.43.10:11434" (laptop running Ollama)
  ollamaModel: "llama3.2:3b",
  defaultCountryCode: "+91"
};
