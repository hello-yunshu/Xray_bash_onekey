import re
import time
import json
import os
from googletrans import Translator

def load_translation_cache(cache_file):
    if os.path.exists(cache_file):
        with open(cache_file, 'r', encoding='utf-8') as f:
            translations = json.load(f)
        
        # 将缓存中的所有翻译结果首字母转为小写
        for key in translations:
            translations[key] = translations[key].capitalize().lower()
        
        return translations
    return {}

def save_translation_cache(cache_file, translations):
    # 在保存缓存前确保所有翻译结果首字母转为小写
    for key in translations:
        translations[key] = translations[key].capitalize().lower()
    
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
    
    # 使用最新的 Translator，并设置更可靠的服务 URL
    translator = Translator(service_urls=['translate.google.com'])
    
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
                    time.sleep(2)  # 增加延迟以避免请求过快
                    # 确保源语言和目标语言设置正确
                    translation = translator.translate(msgid_text, src='auto', dest=target_lang)
                    translated_text = translation.text
                    
                    # 强制将翻译结果的首字母转为小写
                    translated_text = translated_text.capitalize().lower()
                    
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
                    time.sleep(5)  # 重试前等待更长时间
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
    for lang, code in [('en', 'en'), ('fa', 'fa'), ('ru', 'ru')]:
        print(f"\nTranslating to {lang}...")
        input_file = f'po/{lang}.po'
        output_file = f'po/{lang}.po'
        translate_po_file(input_file, output_file, code)