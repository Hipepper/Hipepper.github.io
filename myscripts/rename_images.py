import os
import re


def main():
    # 请将这里的文件名修改为你要处理的 markdown 文件的实际路径
    markdown_file_path = r"C:\Users\Hillstone\gitlab\Hipepper.github.io\source\_posts\一次渗透过程中的CVE-2022-45460撞洞RCE.md"
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



def rename_all_paste():
    import os

    # 指定目标目录
    directory = r"D:\github\Hipepper.github.io\source\_posts\揭露天鹅向量（Swan-Vector）APT组织：针对中国台湾和日本的多阶段DLL植入攻击"

    # 遍历目录下的所有文件
    for filename in os.listdir(directory):
        # 检查文件是否以 "Pasted image " 开头
        if filename.startswith("Pasted image "):
            # 构造新文件名
            new_filename = filename.replace("Pasted image ", "")
            
            # 获取完整路径并进行重命名
            old_file_path = os.path.join(directory, filename)
            new_file_path = os.path.join(directory, new_filename)
            
            os.rename(old_file_path, new_file_path)
            print(f"已重命名: {filename} -> {new_filename}")



if __name__ == "__main__":
    # main()
    rename_all_paste()