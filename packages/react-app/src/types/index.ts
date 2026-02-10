import { IAgentThought, IRetrieverResource, IWorkflowNode } from '@dify-chat/api'

/**
 * 消息对象中的文件 item
 */
export interface IMessageFileItem {
	id: string
	filename: string
	type: string
	url: string
	mime_type: string
	size: number
	transfer_method: string
	belongs_to: string
}

export interface IAgentMessage {
	id?: string
	taskId?: string
	/**
	 * 工作流信息
	 */
	workflows?: {
		/**
		 * 整个工作流的运行状态 running-运行中，finished-已完成
		 */
		status?: 'running' | 'finished'
		/**
		 * 工作流的节点详细信息
		 */
		nodes?: IWorkflowNode[]
	}
	/**
	 * 文件列表
	 */
	files?: IMessageFileItem[]
	/**
	 * 消息主体内容
	 */
	content: string
	/**
	 * 输入变量
	 */
	inputs?: Record<string, unknown>
	/**
	 * 角色
	 */
	role?: string
	/**
	 * Agent 思维链信息
	 */
	agentThoughts?: IAgentThought[]
	/**
	 * 知识库引用列表
	 */
	retrieverResources?: IRetrieverResource[]
}
