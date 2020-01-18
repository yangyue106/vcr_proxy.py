# vcr_proxy.py
a proxy can record HTTP interactions and replay on mock server model.

Web代理基于https://github.com/inaz2/proxy2
录制功能基于https://github.com/kevin1024/vcrpy

# 代码使用:
  ## 录制 
  python2 proxy2.py all [target_host]
  ## 播放
  python2 proxy2.py none

代理监听端口8080
当前只支持HTTP协议，不支持HTTPS协议
