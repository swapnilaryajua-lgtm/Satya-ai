from transformers import pipeline
import spacy
from textblob import TextBlob
import re

# Load once at startup — cached in memory
print("Loading XLM-RoBERTa multilingual model...")
classifier = pipeline(
    "text-classification",
    model="papluca/xlm-roberta-base-language-detection",
    top_k=1
)

print("Loading fake news classifier...")
fake_classifier = pipeline(
    "text-classification",
    model="hamzab/roberta-fake-news-classification",
    truncation=True,
    max_length=512
)

print("Loading spaCy NER...")
nlp = spacy.load("en_core_web_sm")

def detect_language(text: str) -> str:
    try:
        result = classifier(text[:200])[0]
        return result[0]["label"]
    except:
        return "unknown"

def extract_entities(text: str) -> list:
    doc = nlp(text[:1000])
    entities = []
    for ent in doc.ents:
        if ent.label_ in {"PERSON", "ORG", "GPE", "EVENT", "NORP"}:
            entities.append({"text": ent.text, "type": ent.label_})
    return entities[:15]

def get_sentiment(text: str) -> dict:
    blob = TextBlob(text)
    polarity    = round(blob.sentiment.polarity, 3)
    subjectivity = round(blob.sentiment.subjectivity, 3)
    return {
        "polarity": polarity,
        "subjectivity": subjectivity,
        "bias_level": (
            "high"   if subjectivity > 0.6 else
            "medium" if subjectivity > 0.3 else
            "low"
        ),
        "tone": (
            "very negative" if polarity < -0.5 else
            "negative"      if polarity < -0.1 else
            "neutral"       if polarity < 0.1  else
            "positive"      if polarity < 0.5  else
            "very positive"
        )
    }

def find_suspicious_phrases(text: str) -> list:
    patterns = [
        r"\b(BREAKING|URGENT|SHOCKING|EXPLOSIVE|BOMBSHELL)\b",
        r"\b(they don't want you to know|mainstream media won't tell)\b",
        r"\b(100%|absolutely certain|guaranteed|proven fact)\b",
        r"\b(share before deleted|going viral|everyone is saying)\b",
        r"\b(secret|cover.?up|conspiracy|deep state)\b",
    ]
    found = []
    for pattern in patterns:
        matches = re.findall(pattern, text, re.IGNORECASE)
        found.extend(matches)
    return list(set(found))

def analyze_text(text: str) -> dict:
    language     = detect_language(text)
    entities     = extract_entities(text)
    sentiment    = get_sentiment(text)
    suspicious   = find_suspicious_phrases(text)

    try:
        fake_result = fake_classifier(text[:512])[0]
        label       = fake_result["label"].upper()
        confidence  = round(fake_result["score"], 3)
        is_fake     = label in {"FAKE", "LABEL_1", "1"}
    except Exception as e:
        is_fake    = False
        confidence = 0.5
        label      = "UNKNOWN"

    return {
        "language":           language,
        "is_fake":            is_fake,
        "model_label":        label,
        "model_confidence":   confidence,
        "entities":           entities,
        "sentiment":          sentiment,
        "suspicious_phrases": suspicious,
        "word_count":         len(text.split()),
    }