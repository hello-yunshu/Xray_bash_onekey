import re
import time
import json
import os
from openai import OpenAI
from googletrans import Translator

def load_translation_cache(cache_file):
    if os.path.exists(cache_file):
        with open(cache_file, 'r', encoding='utf-8') as f:
            translations = json.load(f)
        
        # 将缓存中的所有翻译结果首字母转为小写并去除末尾标点
        for key in translations:
            translations[key] = translations[key].capitalize().lower().rstrip('.,!?;:')
        
        return translations
    return {}

def save_translation_cache(cache_file, translations):
    # 在保存缓存前确保所有翻译结果首字母转为小写并去除末尾标点
    for key in translations:
        translations[key] = translations[key].capitalize().lower().rstrip('.,!?;:')
    
    with open(cache_file, 'w', encoding='utf-8') as f:
        json.dump(translations, f, ensure_ascii=False, indent=2)

def get_version(version_file):
    if os.path.exists(version_file):
        with open(version_file, 'r', encoding='utf-8') as f:
            return f.read().strip()
    return None

def update_version(version_file):
    timestamp = str(int(time.time()))
    with open(version_file, 'w', encoding='utf-8') as f:
        f.write(timestamp)
    return timestamp

def contains_chinese(text):
    return any('\u4e00' <= char <= '\u9fff' for char in text)

def translate_text_qwen(text, target_lang):
    client = OpenAI(
        api_key=os.getenv("AI_API_KEY"),
        base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
    )
    completion = client.chat.completions.create(
        model="qwen-turbo",
        messages=[
            {'role': 'system', 'content': 'You are a professional text translation assistant, focused on translating short Chinese texts into voice content in the specified target language. Your task is to translate only the Chinese parts of the text into the corresponding target language, leaving English portions as they are. The translation process should not consider context between sentences; ensure each individual sentence is translated accurately. Avoid adding any punctuation at the end of the translated sentences. The goal is to assist in the internationalization of scripts while ensuring translations are concise and accurate.'},
            {'role': 'user', 'content': f'Translate the following text to {target_lang}: {text}'}
        ],
        stream=True
    )
    full_content = ""
    for chunk in completion:
        full_content += chunk.choices[0].delta.content
    return full_content.capitalize().lower().rstrip('.,!?;:')

def translate_text_google(text, target_lang):
    translator = Translator(service_urls=['translate.google.com'])
    translation = translator.translate(text, src='auto', dest=target_lang)
    translated_text = translation.text
    return translated_text.capitalize().lower().rstrip('.,!?;:')

def translate_po_file(input_file, output_file, target_lang):
    # 获取目标语言目录
    lang_dir = os.path.dirname(output_file)
    
    # 构建 LC_MESSAGES 目录路径
    lc_messages_dir = os.path.join('languages', target_lang, 'LC_MESSAGES')
    
    # 确保 LC_MESSAGES 目录存在
    if not os.path.exists(lc_messages_dir):
        os.makedirs(lc_messages_dir)
    
    # 构建缓存文件和版本文件的路径
    cache_file = os.path.join(lang_dir, f'cache_{target_lang}.json')
    version_file = os.path.join(lc_messages_dir, 'version')
    
    translations = load_translation_cache(cache_file)
    current_version = get_version(version_file)
    
    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 匹配msgid和空msgstr
    pattern = r'msgid "(.+?)"\s*\nmsgstr "(.*?)"'
    matches = re.finditer(pattern, content)

    updated = False
    used_translations = set()  # 用于跟踪已使用的翻译

    for match in matches:
        msgid_text = match.group(1)

        # 检查缓存
        if msgid_text in translations:
            translated_text = translations[msgid_text]
            # 直接使用缓存的翻译，不再检查目标语言
            if translated_text == "":
                print(f"Cached translation is empty for: {msgid_text}. Re-translating...")
            else:
                print(f"Using cached translation: {msgid_text} -> {translated_text}")
                # 更新content以反映翻译结果
                content = re.sub(
                    rf'msgid "{re.escape(msgid_text)}"\s*\nmsgstr ".*?"',
                    rf'msgid "{msgid_text}"\nmsgstr "{translated_text}"',
                    content
                )
                updated = True
                used_translations.add(msgid_text)  # 标记为已使用
                continue  # 跳过翻译步骤

        # 进行翻译
        try:
            # 增加重试机制
            max_retries = 3
            for attempt in range(max_retries):
                try:
                    time.sleep(0.1)  # 增加延迟以避免请求过快
                    translated_text = translate_text_qwen(msgid_text, target_lang)
                    
                    # 检查翻译结果是否仍包含中文
                    chinese_retry_count = 0
                    while contains_chinese(translated_text) and chinese_retry_count < 3:
                        print(f"Detected Chinese in translation for: {msgid_text}. Re-translating... (Attempt {chinese_retry_count + 1}/3)")
                        translated_text = translate_text_qwen(msgid_text, target_lang)
                        chinese_retry_count += 1
                    
                    if contains_chinese(translated_text):
                        print(f"Failed to translate {msgid_text} after 3 attempts using Qwen. Using Google Translate...")
                        translated_text = translate_text_google(msgid_text, target_lang)
                    
                    # 检查翻译是否有变更
                    if msgid_text in translations and translations[msgid_text] != translated_text:
                        print(f"Translation changed for: {msgid_text} -> {translated_text}")
                    
                    # 更新缓存
                    translations[msgid_text] = translated_text  # 存储翻译到缓存
                    print(f"New translation [{target_lang}]: {msgid_text} -> {translated_text}")
                    used_translations.add(msgid_text)  # 标记为已使用
                    break  # 成功翻译后跳出重试循环
                except Exception as e:
                    if attempt == max_retries - 1:
                        raise e
                    print(f"Retry {attempt + 1}/{max_retries} for: {msgid_text}")
                    time.sleep(0.3)  # 重试前等待更长时间
        except Exception as e:
            print(f"Translation failed for: {msgid_text}")
            print(f"Error: {e}")
            # 处理翻译失败的情况，删除该条目
            if msgid_text in translations:
                del translations[msgid_text]  # 从缓存中删除该条目
                content = re.sub(rf'msgid "{re.escape(msgid_text)}"\nmsgstr ".*?"\n?', '', content)
                updated = True  # 标记为已更新
                continue  # 继续处理下一个条目

        # 更新content以反映翻译结果
        if translated_text:  # 确保翻译成功
            content = re.sub(
                rf'msgid "{re.escape(msgid_text)}"\s*\nmsgstr ".*?"',
                rf'msgid "{msgid_text}"\nmsgstr "{translated_text}"',
                content
            )
            updated = True
            used_translations.add(msgid_text)  # 标记为已使用

    # 删除未使用的缓存项
    for key in list(translations.keys()):
        if key not in used_translations:
            print(f"Removing unused cache entry: {key}")
            del translations[key]

    if updated:
        save_translation_cache(cache_file, translations)
        new_version = update_version(version_file)
        print(f"Updated version from {current_version} to {new_version}")

    # 确保每个 msgid 和 msgstr 之间没有多余的空格或换行符
    content = re.sub(r'\n\s*msgstr', '\nmsgstr', content)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(content)

if __name__ == '__main__':
    for lang, code in [('en', 'English'), ('fa', 'Persian'), ('ru', 'Russian'), ('ko', 'Korean')]:
        print(f"\nTranslating to {lang} ({code})...")
        input_file = f'po/{lang}.po'
        output_file = f'po/{lang}.po'
        translate_po_file(input_file, output_file, code)