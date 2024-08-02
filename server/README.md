keyManager 含有功能

- 初始化节点密钥信息
- 节点的正常启动
- 重置 5-3 / 2-1 密钥

```text
如果需要实现恢复离线钱包功能
1. copy一份 onlineStartController
2. 修改获取数据由数据库获取改为由客户端输入
3. 获取客户端数据后校验签名
4. 其他流程和在线启动相同， 解密后获取到的是真实密码
5. keymanager 生成一个加密密码， 剩余流程参考 initController
6. mpc 修改自己的密码版本号，或清空数据库
7. mpc 重新从 keymanager 获取密码， 走初始化启动流程
```
