import re
import time
import json
import os
from googletrans import Translator, LANGUAGES
import concurrent.futures

def load_translation_cache(cache_file):
    if os.path.exists(cache_file):
        with open(cache_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_translation_cache(cache_file, translations):
    with open(cache_file, 'w', encoding='utf-8') as f:
        json.dump(translations, f, ensure_ascii=False, indent=2)

def batch_translate(translator, texts, src_lang, dest_lang):
    translations = {}
    max_retries = 3
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_text = {executor.submit(translate_with_retry, translator, text, src_lang, dest_lang, max_retries): text for text in texts}
        for future in concurrent.futures.as_completed(future_to_text):
            text = future_to_text[future]
            try:
                translation = future.result()
                translations[text] = translation
            except Exception as e:
                print(f"Translation failed for: {text}")
                print(f"Error: {e}")
    return translations

def translate_with_retry(translator, text, src_lang, dest_lang, max_retries):
    for attempt in range(max_retries):
        try:
            time.sleep(2)  # 增加延迟以避免请求过快
            translation = translator.translate(text, src=src_lang, dest=dest_lang)
            return translation.text
        except Exception as e:
            if attempt == max_retries - 1:
                raise e
            print(f"Retry {attempt + 1}/{max_retries} for: {text}")
            time.sleep(5)  # 重试前等待更长时间

def translate_po_file(input_file, output_file, target_lang):
    cache_file = f'po/cache_{target_lang}.json'
    translations = load_translation_cache(cache_file)
    
    translator = Translator(service_urls=['translate.google.com'])
    
    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    pattern = r'msgid "(.*?)"\nmsgstr "(.*?)"'
    matches = re.finditer(pattern, content)
    
    texts_to_translate = []
    for match in matches:
        chinese_text = match.group(1)
        if chinese_text and any('\u4e00' <= char <= '\u9fff' for char in chinese_text):
            if chinese_text not in translations:
                texts_to_translate.append(chinese_text)
    
    if texts_to_translate:
        new_translations = batch_translate(translator, texts_to_translate, 'zh-cn', target_lang)
        translations.update(new_translations)
        updated = True
    else:
        updated = False
    
    for match in matches:
        chinese_text = match.group(1)
        existing_translation = match.group(2)
        translated_text = translations.get(chinese_text, existing_translation)
        
        if existing_translation != translated_text:
            content = content.replace(
                f'msgid "{chinese_text}"\nmsgstr "{existing_translation}"',
                f'msgid "{chinese_text}"\nmsgstr "{translated_text}"'
            )
            updated = True
    
    if updated:
        save_translation_cache(cache_file, translations)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(content)

if __name__ == '__main__':
    for lang, code in [('en', 'en'), ('fa', 'fa'), ('ru', 'ru')]:
        print(f"\nTranslating to {lang}...")
        translate_po_file(f'po/{lang}.po', f'po/{lang}.po', code)