# vcr_proxy.py
a proxy can record HTTP interactions and replay on mock server model.

Web代理基于https://github.com/inaz2/proxy2
录制功能基于https://github.com/kevin1024/vcrpy

## 代码使用:
  ### 录制 
  python2 proxy2.py all [target_host]
  ### 播放
  python2 proxy2.py none

---
代理监听端口8080
当前只支持HTTP协议，不支持HTTPS协议


## 播放时，例外处理
本录制代理提供了对url中参数和raw_body的过滤
配置在exclude.json中
其中query下为当前url中query参数的过滤
例如：
    "/path1": ["name", "password"]
    对/path1 中 name 和 password 两个参数不做匹配，即认为这两个参数符合录制文件中对request参数

raw_body 过滤 requestbody中的内容
例如：
    ["/path2","/path3"]
    不校验/path2和/path3中的request_body
