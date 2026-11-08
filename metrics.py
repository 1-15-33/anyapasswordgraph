"""
metrics.py — 10 формул анализа пароля + вердикт Ани.
"""

import math
import difflib
from collections import Counter

WEAK_WORDS = [
    "qwerty", "password", "admin", "123456",
    "letmein", "iloveyou", "monkey", "dragon", "abc123", "111111",
]
SPEEDS = {
    "online":  100,
    "offline": 10**9,
    "quantum": 10**12,
}

def _alphabet_size(password: str) -> int:
    n = 0
    if any(c.islower() for c in password):     n += 26
    if any(c.isupper() for c in password):     n += 26
    if any(c.isdigit() for c in password):     n += 10
    if any(not c.isalnum() for c in password): n += 33
    return n

def shannon_entropy(password: str) -> float:
    if not password: return 0.0
    n = len(password)
    counts = Counter(password)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())

def combinations(password: str) -> float:
    if not password: return 0.0
    n = _alphabet_size(password)
    if n == 0: return 0.0
    return float(n) ** len(password)

def crack_time(password: str, speed: float) -> float:
    c = combinations(password)
    if speed <= 0: return float("inf")
    return c / (2.0 * speed)

def index_of_coincidence(password: str) -> float:
    n = len(password)
    if n < 2: return 0.0
    counts = Counter(password)
    num = sum(c * (c - 1) for c in counts.values())
    den = n * (n - 1)
    return num / den if den else 0.0

def jaccard_bigrams(password: str) -> float:
    if len(password) < 3: return 0.0
    a = {password[i:i+2] for i in range(len(password)-1)}
    b = {password[i:i+2] for i in range(1, len(password)-1)}
    if not a or not b: return 0.0
    return len(a & b) / len(a | b)

def weak_word_similarity(password: str) -> float:
    if not password: return 0.0
    p = password.lower()
    return max(difflib.SequenceMatcher(None, p, w).ratio() for w in WEAK_WORDS)

def chunk_length_cv(password: str) -> float:
    if len(password) < 2: return 0.0
    def cls(c):
        if c.islower(): return "l"
        if c.isupper(): return "U"
        if c.isdigit(): return "d"
        return "s"
    lengths, cur = [], 1
    for i in range(1, len(password)):
        if cls(password[i]) == cls(password[i-1]): cur += 1
        else:
            lengths.append(cur); cur = 1
    lengths.append(cur)
    if len(lengths) < 2: return 0.0
    mu = sum(lengths) / len(lengths)
    if mu == 0: return 0.0
    sigma = math.sqrt(sum((l - mu) ** 2 for l in lengths) / len(lengths))
    return sigma / mu

def type_token_ratio(password: str) -> float:
    if not password: return 0.0
    return len(set(password)) / len(password)

def special_digit_ratio(password: str) -> float:
    if not password: return 0.0
    return sum(1 for c in password if (not c.isalnum()) or c.isdigit()) / len(password)

def normalized_entropy(password: str) -> float:
    if not password: return 0.0
    n = _alphabet_size(password)
    if n <= 1: return 0.0
    denom = math.log2(n)
    if denom == 0: return 0.0
    return min(shannon_entropy(password) / denom, 1.0)

def human_time(seconds: float) -> str:
    if seconds < 1: return "мгновенно"
    if seconds < 60: return f"{int(seconds)} сек"
    if seconds < 3600: return f"{int(seconds / 60)} мин"
    if seconds < 86400: return f"{int(seconds / 3600)} ч"
    if seconds < 31_536_000: return f"{int(seconds / 86400)} дней"
    
    years = seconds / 31_536_000
    if years < 1000: 
        return f"{int(years)} лет"
    
    centuries = years / 100
    if centuries > 1_000_000_000:
        return "> миллиарда веков"
    if centuries > 1_000_000:
        return f"{int(centuries / 1_000_000)} млн веков"
    return f"{int(centuries)} веков"

def human_factor(password: str) -> float:
    penalty = 0
    if any('а' <= c <= 'я' or 'А' <= c <= 'Я' for c in password):
        penalty += 50 
    keyboard_rows = "1234567890qwertyuiopasdfghjklzxcvbnm"
    for i in range(len(password) - 2):
        if password[i:i+3].lower() in keyboard_rows:
            penalty += 30
            break
    if len(set(password)) < len(password) * 0.4:
        penalty += 20
    return min(100, penalty)

def verdict(metrics: dict, times: dict, password: str) -> str:
    score = 0
    if metrics["shannon_entropy"] < 3.0:       score += 25
    if metrics["weak_word_similarity"] > 0.8:  score += 25
    if metrics["type_token_ratio"] < 0.5:      score += 15
    if metrics["index_of_coincidence"] > 0.05: score += 10
    if metrics["jaccard_bigrams"] > 0.5:       score += 10
    if metrics["normalized_entropy"] < 0.6:    score += 15
    
    h_penalty = human_factor(password)
    score += h_penalty
    score = min(100, score)
    
    offline = times.get("offline_human", "?")

    if score >= 70:
        return (f"Аня говорит: этот пароль взломают быстрее, чем ты моргнёшь. "
                f"Офлайн: {offline}.")
    elif score >= 40:
        return (f"Аня говорит: слабовато. Офлайн-взлом за {offline}. "
                f"Добавь длины и спецсимволов.")
    else:
        advice = []
        if metrics["special_digit_ratio"] < 0.3: advice.append("спецсимволов")
        if metrics["normalized_entropy"] < 0.8: advice.append("предсказуемости поменьше")
        advice_str = ", ".join(advice) if advice else "длины"
        return (f"Аня говорит: норм, но вот что улучшить: {advice_str}. "
                f"Офлайн-взлом за {offline}.")

def analyze(password: str) -> dict:
    metrics = {
        "shannon_entropy":      round(shannon_entropy(password), 4),
        "combinations":         combinations(password),
        "index_of_coincidence": round(index_of_coincidence(password), 4),
        "jaccard_bigrams":      round(jaccard_bigrams(password), 4),
        "weak_word_similarity": round(weak_word_similarity(password), 4),
        "chunk_length_cv":      round(chunk_length_cv(password), 4),
        "type_token_ratio":     round(type_token_ratio(password), 4),
        "special_digit_ratio":  round(special_digit_ratio(password), 4),
        "normalized_entropy":   round(normalized_entropy(password), 4),
        "alphabet_size":        _alphabet_size(password),
        "length":               len(password),
    }
    
    h_penalty = human_factor(password)
    times = {}
    
    for name, spd in SPEEDS.items():
        if h_penalty >= 50:
            effective_combinations = 50000
            t = effective_combinations / (2.0 * spd)
        elif h_penalty >= 30:
            effective_combinations = 10_000_000
            t = effective_combinations / (2.0 * spd)
        else:
            t = crack_time(password, spd)
            
        times[name] = t
        if t == float("inf") or t > 1e30:
            times[f"{name}_human"] = "> миллиарда веков"
        else:
            times[f"{name}_human"] = human_time(t)

    return {"metrics": metrics, "times": times, "verdict": verdict(metrics, times, password)}
