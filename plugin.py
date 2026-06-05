"""
加群申请处理插件。
by：白狐 & claude
"""

from __future__ import annotations

import asyncio
import base64
import hmac
import json
import os
from hashlib import sha1
from typing import Any, ClassVar, Dict, List, Optional

import aiohttp
from aiohttp import web

from maibot_sdk import (
    CONFIG_RELOAD_SCOPE_SELF,
    Command,
    Field,
    MaiBotPlugin,
    PluginConfigBase,
)


# ---------------- 配置模型 ----------------


class PluginSection(PluginConfigBase):
    __ui_label__: ClassVar[str] = "插件设置"
    __ui_order__: ClassVar[int] = 0

    enabled: bool = Field(
        default=True,
        description="是否启用本插件。",
        json_schema_extra={"label": "启用插件", "order": 0},
    )
    config_version: str = Field(
        default="1.0.0",
        json_schema_extra={"disabled": True, "hidden": True, "label": "配置版本", "order": 99},
    )


class AdminSection(PluginConfigBase):
    __ui_label__: ClassVar[str] = "管理员"
    __ui_order__: ClassVar[int] = 1

    admin_qqs: List[str] = Field(
        default_factory=list,
        description="Bot 管理员 QQ 号列表；加群申请会推送到通知群，且只有管理员/群主能用 /同意 /拒绝。",
        json_schema_extra={"label": "管理员 QQ", "order": 0, "placeholder": "请输入 QQ 号"},
    )


class WebhookSection(PluginConfigBase):
    __ui_label__: ClassVar[str] = "Webhook"
    __ui_order__: ClassVar[int] = 2

    host: str = Field(
        default="127.0.0.1",
        description="监听 NapCat HTTP 上报的本地地址。",
        json_schema_extra={"label": "监听地址", "order": 0, "placeholder": "127.0.0.1"},
    )
    port: int = Field(
        default=18081, ge=1, le=65535,
        description="监听端口，需要和 NapCat HTTP 客户端配置中的端口一致。",
        json_schema_extra={"label": "监听端口", "order": 1, "step": 1},
    )
    path: str = Field(
        default="/maibot/group_request",
        description="HTTP 路径，NapCat 的 URL 应填成 http://host:port/path。",
        json_schema_extra={"label": "HTTP 路径", "order": 2, "placeholder": "/maibot/group_request"},
    )
    secret: str = Field(
        default="",
        description="可选 secret，对应 NapCat 「HTTP 客户端」的 token，留空则不校验。",
        json_schema_extra={"label": "Secret", "order": 3, "input_type": "password"},
    )



class NoticeSection(PluginConfigBase):
    __ui_label__: ClassVar[str] = "申请通知"
    __ui_order__: ClassVar[int] = 3

    send_avatar: bool = Field(
        default=True,
        description="推送加群申请通知时，在文本上方附带申请方的 QQ 头像。",
        json_schema_extra={"label": "附带头像", "order": 0},
    )
    avatar_size: int = Field(
        default=640, ge=40, le=640,
        description="头像尺寸（像素），常用值: 100/140/640。",
        json_schema_extra={"label": "头像尺寸", "order": 1, "step": 1},
    )


class GroupRequestHandlerConfig(PluginConfigBase):
    plugin: PluginSection = Field(default_factory=PluginSection)
    admin: AdminSection = Field(default_factory=AdminSection)
    webhook: WebhookSection = Field(default_factory=WebhookSection)
    notice: NoticeSection = Field(default_factory=NoticeSection)


# ---------------- 插件主体 ----------------

class GroupRequestHandlerPlugin(MaiBotPlugin):
    config_model = GroupRequestHandlerConfig

    _runner: Optional[web.AppRunner]
    _site: Optional[web.BaseSite]
    # "user_id:group_id" -> {"flag": str, "comment": str, "group_id": str, "user_id": str}
    _pending: Dict[str, Dict[str, Any]]
    _notified_flags: set
    _data_path: str

    async def on_load(self) -> None:
        self._runner = None
        self._site = None
        self._pending = {}
        self._notified_flags = set()

        data_dir = os.path.join(os.path.dirname(__file__), "data")
        os.makedirs(data_dir, exist_ok=True)
        self._data_path = os.path.join(data_dir, "state.json")
        self._load_state()

        if self.config.plugin.enabled:
            await self._start_webhook()
        self.ctx.logger.info("加群申请处理插件已加载")

    async def on_unload(self) -> None:
        await self._stop_webhook()
        self._save_state()

    async def on_config_update(self, scope: str, config_data: Dict[str, Any], version: str) -> None:
        if scope != CONFIG_RELOAD_SCOPE_SELF:
            return
        del config_data
        del version

        await self._stop_webhook()
        if self.config.plugin.enabled:
            await self._start_webhook()

    # ---------------- Webhook 服务 ----------------

    async def _start_webhook(self) -> None:
        webhook = self.config.webhook
        path = webhook.path if webhook.path.startswith("/") else f"/{webhook.path}"

        app = web.Application()
        app.router.add_post(path, self._handle_webhook)

        self._runner = web.AppRunner(app)
        await self._runner.setup()
        try:
            self._site = web.TCPSite(self._runner, webhook.host, int(webhook.port))
            await self._site.start()
        except OSError as exc:
            self.ctx.logger.error(
                f"加群申请 webhook 监听失败 host={webhook.host} port={webhook.port}: {exc}"
            )
            await self._stop_webhook()
            return

        self.ctx.logger.info(
            f"加群申请 webhook 已监听: http://{webhook.host}:{webhook.port}{path}"
        )

    async def _stop_webhook(self) -> None:
        site = self._site
        runner = self._runner
        self._site = None
        self._runner = None
        try:
            if site is not None:
                await site.stop()
        except Exception as exc:
            self.ctx.logger.warning(f"停止 webhook 监听失败: {exc}")
        try:
            if runner is not None:
                await runner.cleanup()
        except Exception as exc:
            self.ctx.logger.warning(f"清理 webhook 资源失败: {exc}")

    async def _handle_webhook(self, request: web.Request) -> web.Response:
        raw = await request.read()
        if not self._verify_signature(request, raw):
            return web.Response(status=401, text="invalid signature")

        try:
            payload = json.loads(raw.decode("utf-8") or "{}")
        except Exception:
            return web.Response(status=400, text="invalid json")

        if not isinstance(payload, dict):
            return web.Response(status=400, text="invalid payload")

        post_type = str(payload.get("post_type") or "").strip()
        request_type = str(payload.get("request_type") or "").strip()
        sub_type = str(payload.get("sub_type") or "").strip()
        if post_type == "request" and request_type == "group" and sub_type == "add":
            asyncio.create_task(self._on_group_request(payload))
        return web.json_response({})

    def _verify_signature(self, request: web.Request, raw: bytes) -> bool:
        secret = (self.config.webhook.secret or "").strip()
        if not secret:
            return True
        signature = request.headers.get("X-Signature", "")
        if not signature.startswith("sha1="):
            return False
        expected = "sha1=" + hmac.new(secret.encode("utf-8"), raw, sha1).hexdigest()
        return hmac.compare_digest(signature, expected)

    async def _on_group_request(self, payload: Dict[str, Any]) -> None:
        try:
            user_id = str(payload.get("user_id") or "").strip()
            group_id = str(payload.get("group_id") or "").strip()
            flag = str(payload.get("flag") or "").strip()
            comment = str(payload.get("comment") or "").strip()
            if not user_id or not flag or not group_id:
                return

            admin_qqs = self._normalized_admin_qqs()
            if not admin_qqs:
                self.ctx.logger.warning("收到加群申请但未配置 admin_qqs，无法推送")
                return

            pending_key = f"{user_id}:{group_id}"
            self._pending[pending_key] = {
                "flag": flag, "comment": comment,
                "group_id": group_id, "user_id": user_id,
            }
            if flag in self._notified_flags:
                return
            self._notified_flags.add(flag)
            self._save_state()

            notice_text = await self._build_notice_text(user_id, group_id, comment)
            await self._send_group_notice(group_id, user_id, notice_text)
            self.ctx.logger.info(f"已推送加群申请: user_id={user_id} group_id={group_id}")
        except Exception as exc:
            self.ctx.logger.warning(f"处理加群申请失败: {exc}")

    # ---------------- 资料组装 ----------------

    async def _build_notice_text(self, user_id: str, group_id: str, comment: str) -> str:
        info = await self._call_napcat(
            "get_stranger_info",
            {"user_id": int(user_id) if user_id.isdigit() else user_id, "no_cache": True},
        )
        info_data = info.get("data", info) if isinstance(info, dict) else info
        if not isinstance(info_data, dict):
            info_data = {}

        lines: List[str] = ["📨 收到新的加群申请"]

        def add(label: str, value: Any) -> None:
            text = "" if value is None else str(value).strip()
            if not text or text in {"0", "0.0", "unknown"}:
                return
            lines.append(f"{label}: {text}")

        nickname = str(info_data.get("nickname") or "").strip()
        add("申请人QQ", user_id)
        add("昵称", nickname)
        add("目标群号", group_id)
        add("性别", self._format_sex(info_data.get("sex")))
        add("年龄", info_data.get("age"))
        add("等级", info_data.get("level") or info_data.get("qqLevel"))
        add("个性签名", info_data.get("long_nick") or info_data.get("longNick") or info_data.get("sign"))
        if comment:
            lines.append(f"验证消息: {comment}")

        lines.append("")
        lines.append(f"同意入群请发送：/同意入群 {user_id}")
        lines.append(f"拒绝入群请发送：/拒绝入群 {user_id}")
        return "\n".join(lines)

    @staticmethod
    def _format_sex(value: Any) -> str:
        text = str(value or "").strip().lower()
        return {"male": "男", "female": "女", "0": "男", "1": "女"}.get(text, "")

    # ---------------- 命令 ----------------

    @Command(
        "approve_group",
        description="管理员/群主同意指定 QQ 的加群申请",
        pattern=r"^/同意入群\s+(?P<target_qq>\d+)\s*$",
    )
    async def handle_approve(self, stream_id: str = "", **kwargs: Any) -> tuple:
        return await self._handle_decision(approve=True, stream_id=stream_id, **kwargs)

    @Command(
        "reject_group",
        description="管理员/群主拒绝指定 QQ 的加群申请",
        pattern=r"^/拒绝入群\s+(?P<target_qq>\d+)\s*$",
    )
    async def handle_reject(self, stream_id: str = "", **kwargs: Any) -> tuple:
        return await self._handle_decision(approve=False, stream_id=stream_id, **kwargs)

    async def _handle_decision(self, approve: bool, stream_id: str, **kwargs: Any) -> tuple:
        if not self._is_group_context(kwargs):
            return False, None, False

        sender_qq = self._extract_sender_qq(kwargs)
        if sender_qq is None:
            return False, None, False

        if not self._is_authorized(sender_qq, kwargs):
            return False, None, False

        matched_groups = kwargs.get("matched_groups") or {}
        target_qq = str(matched_groups.get("target_qq") or "").strip()
        if not target_qq:
            return False, "用法：/同意入群 <QQ号> 或 /拒绝入群 <QQ号>", True

        record = self._find_pending(target_qq)
        if record is None:
            await self._reply(
                stream_id,
                f"未找到 QQ {target_qq} 的加群申请，可能已经处理过或 webhook 未收到。",
            )
            return True, None, True

        flag = record.get("flag", "")
        group_id = record.get("group_id", "")

        params: Dict[str, Any] = {
            "flag": flag,
            "sub_type": "add",
            "approve": bool(approve),
        }

        try:
            await self._call_napcat("set_group_add_request", params, raise_on_error=True)
        except Exception as exc:
            await self._reply(stream_id, f"处理失败：{exc}")
            return False, None, True

        pending_key = f"{target_qq}:{group_id}"
        self._pending.pop(pending_key, None)
        self._notified_flags.discard(flag)
        self._save_state()

        if approve:
            await self._reply(stream_id, f"已同意 QQ {target_qq} 加入群 {group_id}。")
        else:
            await self._reply(stream_id, f"已拒绝 QQ {target_qq} 加入群 {group_id}。")
        return True, None, True

    # ---------------- 辅助 ----------------

    @staticmethod
    def _is_group_context(kwargs: Dict[str, Any]) -> bool:
        base_info = kwargs.get("message_base_info") or {}
        if isinstance(base_info, dict):
            if base_info.get("group_id") or base_info.get("group_info"):
                return True
        return bool(kwargs.get("group_id"))

    def _is_authorized(self, sender_qq: str, kwargs: Dict[str, Any]) -> bool:
        if sender_qq in self._normalized_admin_qqs():
            return True
        base_info = kwargs.get("message_base_info") or {}
        if isinstance(base_info, dict):
            sender_info = base_info.get("user_info") or {}
            if isinstance(sender_info, dict):
                role = str(sender_info.get("role") or "").strip().lower()
                if role in ("owner", "admin"):
                    return True
        return False

    def _find_pending(self, target_qq: str) -> Optional[Dict[str, Any]]:
        for key, record in self._pending.items():
            if record.get("user_id") == target_qq:
                return record
        return None

    def _normalized_admin_qqs(self) -> List[str]:
        return [str(qq).strip() for qq in self.config.admin.admin_qqs if str(qq).strip()]

    @staticmethod
    def _extract_sender_qq(kwargs: Dict[str, Any]) -> Optional[str]:
        base_info = kwargs.get("message_base_info") or {}
        user_info = base_info.get("user_info") if isinstance(base_info, dict) else {}
        sender_qq = (
            kwargs.get("user_id")
            or (user_info.get("user_id") if isinstance(user_info, dict) else None)
        )
        if sender_qq in (None, ""):
            return None
        return str(sender_qq).strip()

    async def _reply(self, stream_id: str, text: str) -> None:
        if not stream_id or not text:
            return
        try:
            await self.ctx.send.text(text, stream_id)
        except Exception as exc:
            self.ctx.logger.warning(f"回复消息失败: {exc}")

    async def _send_group_notice(self, group_id: str, applicant_qq: str, text: str) -> None:
        if not group_id or not text:
            return

        message: List[Dict[str, Any]] = []
        if self.config.notice.send_avatar and applicant_qq:
            size = int(self.config.notice.avatar_size or 640)
            avatar_b64 = await self._fetch_avatar_base64(applicant_qq, size=size)
            if avatar_b64:
                message.append({"type": "image", "data": {"file": f"base64://{avatar_b64}"}})
        message.append({"type": "text", "data": {"text": text}})

        await self._call_napcat(
            "send_group_msg",
            {
                "group_id": int(group_id) if str(group_id).isdigit() else group_id,
                "message": message,
            },
            raise_on_error=False,
        )

    async def _fetch_avatar_base64(
        self, qq: str, size: int = 640, timeout_sec: int = 10
    ) -> Optional[str]:
        urls = [
            f"https://q1.qlogo.cn/g?b=qq&nk={qq}&s={size}",
            f"https://q.qlogo.cn/g?b=qq&nk={qq}&s={size}",
        ]
        timeout = aiohttp.ClientTimeout(total=timeout_sec)
        try:
            async with aiohttp.ClientSession(timeout=timeout) as session:
                for url in urls:
                    try:
                        async with session.get(url) as resp:
                            if resp.status == 200:
                                data = await resp.read()
                                if data:
                                    return base64.b64encode(data).decode("utf-8")
                    except Exception as exc:
                        self.ctx.logger.debug(f"头像下载失败 {url}: {exc}")
                        continue
        except Exception as exc:
            self.ctx.logger.warning(f"头像下载会话错误: {exc}")
        return None

    async def _call_napcat(
        self,
        action_name: str,
        params: Dict[str, Any],
        raise_on_error: bool = False,
    ) -> Any:
        try:
            response = await self.ctx.api.call(
                "adapter.napcat.action.call",
                action_name=action_name,
                params=params,
            )
        except Exception as exc:
            if raise_on_error:
                raise
            self.ctx.logger.debug(f"调用 NapCat 动作 {action_name} 失败: {exc}")
            return None

        if isinstance(response, dict) and str(response.get("status", "")).lower() not in {"", "ok"}:
            error_text = str(response.get("wording") or response.get("message") or response.get("retcode"))
            if raise_on_error:
                raise RuntimeError(f"NapCat 动作 {action_name} 返回错误: {error_text}")
            self.ctx.logger.debug(f"NapCat 动作 {action_name} 返回非 ok 状态: {error_text}")
        return response

    # ---------------- 持久化 ----------------

    def _load_state(self) -> None:
        try:
            with open(self._data_path, "r", encoding="utf-8") as fp:
                payload = json.load(fp)
            pending = payload.get("pending")
            if isinstance(pending, dict):
                self._pending = {str(k): dict(v) for k, v in pending.items() if isinstance(v, dict)}
            notified = payload.get("notified_flags")
            if isinstance(notified, list):
                self._notified_flags = {str(item) for item in notified}
        except FileNotFoundError:
            return
        except Exception as exc:
            self.ctx.logger.warning(f"读取加群申请状态失败: {exc}")

    def _save_state(self) -> None:
        payload = {
            "pending": self._pending,
            "notified_flags": sorted(self._notified_flags),
        }
        try:
            with open(self._data_path, "w", encoding="utf-8") as fp:
                json.dump(payload, fp, ensure_ascii=False, indent=2)
        except Exception as exc:
            self.ctx.logger.warning(f"保存加群申请状态失败: {exc}")


def create_plugin() -> GroupRequestHandlerPlugin:
    return GroupRequestHandlerPlugin()
