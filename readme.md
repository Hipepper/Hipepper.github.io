# 本地blog使用

1. 先克隆到本地，`dev`分支存放原始博客环境，`master`分支是`hexo g | hexo s`生成的博客内容；
2. 新增博客`hexo new`;
3. 写完博客`hexo g | hexo s`生成本地测试；
4. 测试完毕之后，先push dev环境到仓库，保持代码最新`git add *,git commit -m ...,git push origin dev`
5. 发布博文`hexo deploy`,会把public目录下文件上传到`main`分支里面；

# refer
`https://juejin.cn/post/7342765395901743113`


