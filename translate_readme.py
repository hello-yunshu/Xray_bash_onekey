import os
import json
import re
import markdown
from bs4 import BeautifulSoup
from googletrans import Translator
import logging

# 设置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_translation_cache(cache_file):
    if os.path.exists(cache_file):
        with open(cache_file, 'r', encoding='utf-8') as f:
            return json.load(f)
    return {}

def save_translation_cache(cache_file, translations):
    with open(cache_file, 'w', encoding='utf-8') as f:
        json.dump(translations, f, ensure_ascii=False, indent=4)

def get_cache_key(text, target_lang):
    """生成缓存键，将文本和目标语言合并为一个字符串"""
    return f"{target_lang}::{text}"

def translate_text(text, target_lang, translator, translations):
    cache_key = get_cache_key(text, target_lang)
    if cache_key in translations:
        logging.info(f"从缓存中获取翻译: '{text}' -> '{translations[cache_key]}'")
        return translations[cache_key]
    
    try:
        translation = translator.translate(text, dest=target_lang)
        translations[cache_key] = translation.text
        logging.info(f"翻译成功: '{text}' -> '{translation.text}'")
        return translation.text
    except Exception as e:
        logging.error(f"翻译失败: {text}\n错误: {e}")
        return text  # 返回原始文本以防翻译失败

def should_translate(segment):
    """判断是否需要翻译该段落"""
    # 定义需要跳过翻译的模式
    skip_patterns = [
        r'\[简体中文\]\(README\.md\)',  # 只要匹配到[简体中文](README.md)，就跳过该段落
        r'\[.*\]\(.*\)'  # 跳过所有包含 markdown 链接的段落
    ]
    for pattern in skip_patterns:
        if re.search(pattern, segment):
            logging.info(f"跳过翻译的段落: {segment}")
            return False
    return True

def extract_text_segments(content):
    """
    使用 Markdown 解析库提取非代码块的文本段落。
    """
    html = markdown.markdown(content)
    soup = BeautifulSoup(html, 'html.parser')
    # 移除所有代码块
    for code in soup.find_all(['code', 'pre']):
        code.extract()
    # 获取纯文本
    text = soup.get_text()
    # 按段落分割
    segments = text.split('\n\n')
    # 清理段落
    segments = [segment.strip() for segment in segments if segment.strip()]
    logging.info(f"提取到 {len(segments)} 个文本段落进行翻译。")
    return segments

def replace_translation(original_content, translated_segments):
    """
    将翻译后的文本段落重新插入到原始内容中，保持代码块不变。
    """
    pattern = re.compile(r'```[\s\S]*?```', re.MULTILINE)
    parts = pattern.findall(original_content)
    result = ""
    translated_iter = iter(translated_segments)
    
    splitted = pattern.split(original_content)
    for i, part in enumerate(splitted):
        translated_text = next(translated_iter, "")
        result += translated_text + "\n\n"
        if i < len(parts):
            result += parts[i] + "\n\n"
    return result.strip()

def translate_readme(input_file, output_dir):
    # 创建翻译缓存并加载
    cache_file = 'translation_cache.json'
    translations = load_translation_cache(cache_file)
    logging.info(f"缓存文件 '{cache_file}' 加载完成，共有 {len(translations)} 条缓存记录。")

    # 初始化翻译器
    translator = Translator(service_urls=['translate.google.com'])
    logging.info("翻译器初始化完成。")

    # 读取 README.md 内容
    with open(input_file, 'r', encoding='utf-8') as f:
        content = f.read()
    logging.info(f"读取 '{input_file}' 完成，共 {len(content)} 个字符。")

    # 提取非代码块的文本段落
    text_segments = extract_text_segments(content)
    logging.info(f"提取到 {len(text_segments)} 个文本段落。")

    # 定义目标语言
    languages = {
        'en': 'english',
        'ru': 'russian',
        'fa': 'persian'
    }

    # 获取源文件名
    source_filename = os.path.basename(input_file)

    for lang_code, lang_name in languages.items():
        logging.info(f"开始翻译到 {lang_name} ({lang_code})")
        translated_segments = []
        for idx, segment in enumerate(text_segments, 1):
            # 判断是否需要翻译
            if should_translate(segment) and re.search(r'[\u4e00-\u9fff]', segment):
                translated = translate_text(segment, lang_code, translator, translations)
                translated_segments.append(translated)
                logging.debug(f"段落 {idx} 翻译为 {lang_name}：{translated}")
            else:
                translated_segments.append(segment)
                logging.debug(f"段落 {idx} 不需要翻译，保持原样。")
        
        # 重新组合内容，保留代码块
        translated_content = replace_translation(content, translated_segments)
        logging.info(f"{lang_name} 翻译内容重新组合完成。")

        # 定义目标语言的目录
        lang_dir = os.path.join(output_dir, 'languages', lang_code)
        os.makedirs(lang_dir, exist_ok=True)

        # 定义输出文件路径，保持与源文件名一致
        output_file = os.path.join(lang_dir, source_filename)
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(translated_content)
        logging.info(f"{lang_name} 翻译完成，文件保存至: {output_file}")

    # 保存翻译缓存
    save_translation_cache(cache_file, translations)
    logging.info("所有翻译完成，并已保存缓存。")

if __name__ == "__main__":
    input_readme = 'README.md'  # 源文件路径
    output_directory = '.'      # 输出目录，可以根据需要修改
    translate_readme(input_readme, output_directory) 