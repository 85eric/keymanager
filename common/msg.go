package common

type MsgType int

// 客户端消息类型
const (
	// MsgTypeInit 客户端链接时请求信息， 标识客户端身份
	MsgTypeInit MsgType = 0
	// MsgTypeNormal 普通文本信息
	MsgTypeNormal MsgType = 1
	// MsgTypeSyncVersion 同步服务端及客户端版本号
	MsgTypeSyncVersion MsgType = 2
	// MsgTypeWaitInput 等待客户端输入信息
	MsgTypeWaitInput MsgType = 3
	// MsgTypeSyncMPCNodeNeed 将 mpc 节点初始化需要的数据发送给 mpc 节点对应客户端
	MsgTypeSyncMPCNodeNeed MsgType = 4
	// MsgTypeReply 客户端或服务端响应信息
	MsgTypeReply MsgType = 5
	// MsgTypeChangeClientStatus 客户端修改当前链接要做的业务
	MsgTypeChangeClientStatus = 6
	// MsgTypeSyncOfflineNeed 离线客户端需要保存的信息
	MsgTypeSyncOfflineNeed MsgType = 7
	// MsgTypeNeedReInput 需要客户端重新输入密码
	MsgTypeNeedReInput MsgType = 8
	// MsgTypeCheckOldSecret 等待客户端输入信息
	MsgTypeCheckOldSecret MsgType = 9

	// MsgTypeInitFinish 客户端链接时请求信息， 标识客户端身份
	MsgTypeInitFinish MsgType = 10
	// MsgTypeRegisterFinish 所有客户端链接完成
	MsgTypeInitMPCRegisterFinish MsgType = 11

	// MsgTypeGenerateFinish 业务成功完成
	MsgTypeFinish MsgType = 100

	// MsgTypeLossConn 服务端 丢失某一个客户端链接
	MsgTypeLossConn MsgType = 9001
	// MsgTypeRefuse 已经有相同类型及index的客户端链接上了服务端
	MsgTypeRefuse MsgType = 9002
	// MsgTypeNeedRestart 服务器发生错误，需要客户端重新链接
	MsgTypeNeedRestart MsgType = 9003
)

type Msg struct {
	Version  int64   `json:"version"`
	MsgType  MsgType `json:"msg_type"`
	MsgIndex int64   `json:"msg_index"`
	Data     []byte  `json:"data"`
}

type InitMsg struct {
	ClientStatus ClientStatus `json:"client_status"`
	ClientType   ClientType   `json:"client_type"`
	Index        int          `json:"index"`
}

type SyncMPCNodeNeedMsg struct {
	NodeKey []byte
	TrueKey []byte
}

func (receiver *Msg) String() string {
	return string(receiver.Data)
}
