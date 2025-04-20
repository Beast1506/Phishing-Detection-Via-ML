# 🛡️ Phishing URL Detection via Machine Learning

This web app helps users identify whether a given URL is **legitimate** or potentially a **phishing website** using a machine learning model.

🌐 **Live App:**  
👉 [Try it on Streamlit](https://phishing-detection-via-ml.streamlit.app/)

---

## 🚀 Features

- ✅ Real-time phishing detection
- 📊 Displays confidence score and extracted URL features
- 🧠 Uses a trained Random Forest model
- 🕘 Keeps history of checked URLs during session

---

---

## 🧪 How It Works

1. User inputs a full URL (with `http://` or `https://`)
2. The app extracts meaningful features from the URL such as:
   - Length of URL and domain
   - Number of special characters
   - Use of suspicious keywords
   - Domain entropy
   - HTTPS presence
   - etc.
3. A trained Random Forest model classifies the URL as either:
   - ✅ **Legitimate**
   - ❌ **Phishing**
4. The app displays the result with a confidence percentage.

---
## 📄 License
This project is licensed under the MIT License.
You are free to use, modify, and distribute this software with proper attribution.
See the LICENSE file for more details.

