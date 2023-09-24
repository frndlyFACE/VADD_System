import requests
from bs4 import BeautifulSoup
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.ensemble import RandomForestClassifier
import sys
import joblib
from datetime import datetime

model = joblib.load('Vrf_classifier.pkl')
vectorizer = joblib.load('Vtfidf_vectorizer.pkl')

#url = "https://nishaoverseas.in/"
#url = "https://google.com/"

url = sys.argv[1]

current_datetime = datetime.now().strftime("%H:%M:%S %d/%m/%y")
print(f"[{current_datetime}]")
print("URL:",url)

response = requests.get(url)

if response.status_code == 200:
    soup = BeautifulSoup(response.text, "html.parser")

    human_readable_content = " ".join(soup.stripped_strings)

    input_text = [human_readable_content]
    input_text_tfidf = vectorizer.transform(input_text)

    prediction = model.predict(input_text_tfidf)

    if prediction[0] == 1:
        print("The website appears to be defaced.")
    else:
        print("The website appears to be normal.")
else:
    print("Failed to retrieve the webpage")
print("\n")