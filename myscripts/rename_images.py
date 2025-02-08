import os
import re


def main():
    # 请将这里的文件名修改为你要处理的 markdown 文件的实际路径
    markdown_file_path = r"C:\Users\Hillstone\gitlab\Hipepper.github.io\source\_posts\评估现代网络协议指纹识别技术：加固堡垒机防御.md"
    file_dir = os.path.dirname(markdown_file_path)
    file_name = os.path.basename(markdown_file_path).split('.')[0]
    new_dir = os.path.join(file_dir, file_name)
    if not os.path.exists(new_dir):
        os.makedirs(new_dir)

    with open(markdown_file_path, 'r', encoding='utf-8') as file:
        content = file.read()
    # 正则表达式用于匹配 markdown 中的图片链接
    pattern = re.compile(r'!\[(.*?)\]\(assets/(.*?)\)')
    def replace_image(match):
        alt_text = match.group(1)
        image_name = match.group(2)
        base_image_name = os.path.basename(image_name)
        # base_image_name = image_name.split('.')[0]
        
        # 确保 [] 中的文件名和图片文件名一致
        new_alt_text = base_image_name.split('.')[0]
        return f'![{new_alt_text}]({file_name}/{image_name})'
    new_content = pattern.sub(replace_image, content)

    with open(markdown_file_path, 'w', encoding='utf-8') as file:
        file.write(new_content)


if __name__ == "__main__":
    main()