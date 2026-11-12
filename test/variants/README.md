# WASI 描述符能力状态模型与不可恢复性验证

本目录配合两个测试文件，证明 WASI preview1 描述符一旦放弃某项文件权限，
无法通过**描述符重编号、派生句柄或错误重试**重新获得它。

## 文件

- `../capmodel.py`：与实现无关的能力状态模型（纯 Python，无 I/O）。
- `../capability_wasi.py`：用真实临时目录驱动 `pywasm.wasi.Preview1`，
  逐转换与模型比对，并枚举每个可访问对象的允许动作。
- `M_retry-drop-recovery.patch`：错误重试通道的最小恢复变体。
- `M_renumber-rights-union.patch`：重编号通道的最小恢复变体（跨 T_drop/T_renumber）。
- `M_derive-overgrant.patch`：派生句柄通道的最小恢复变体。

运行：

```sh
python test/capability_wasi.py          # 干净源码：应打印 PASS，退出码 0
git apply test/variants/<补丁>           # 注入某个错误变体
python test/capability_wasi.py          # 应在命名转换上断言失败，退出码 1
git apply -R test/variants/<补丁>        # 还原
```

## 能力状态模型

每个描述符编号绑定一条能力 `Cap(obj, base, root, relinquished, status)`：

- `base`：当前可执行的权限位（`help_perm` 的门禁依据）。
- `root`：可被派生句柄继承的权限天花板。
- `relinquished`：该编号通过 `T_drop` 主动放弃过的位，只增不减。
- `status`：opened / closed。

转换：

| 转换 | 模型操作 | 真实实现入口 | 安全约束 |
| --- | --- | --- | --- |
| `T_open` | 分配全新编号，权限受 parent.root 限制 | `path_open` | 新编号有全新 relinquished，不恢复任何旧描述符的位 |
| `T_drop` | 仅当新掩码是旧掩码子集才接受，移除位进 relinquished | `fd_fdstat_set_rights` | 单调降权，超集请求返回 NOTCAPABLE 且状态不变 |
| `T_renumber` | 源能力整体转移到目标，源同时关闭 | `fd_renumber` | 结果不得包含源不持有的位；源必须关闭 |
| `T_close` | 编号标记死亡，不回收 | `fd_close` | 再访问得 BADF，新 open 取新编号 |
| `T_action` | 仅当 base 持位才允许 | `fd_read/fd_write/fd_seek/...` | 每次动作独立走 `help_perm` |

核心不变量 `assert_no_recovery`：除 `T_open` 外，任何转换后
`base & relinquished_before == 0`；`T_renumber` 额外要求结果掩码是源掩码
子集且源已关闭。违反时断言会打印**具体转换名、描述符编号和恢复的权限位**，
而不是只比较返回码。

## 实测场景（test/capability_wasi.py）

- A 开关：经预打开目录 `path_open` 出 RW/RO 句柄，打印访问矩阵。
- B 降权+重试：RW 降为 RO 后 `fd_write` 得 NOTCAPABLE；再次申请 WRITE 被
  拒且掩码不变（失败原子性）。
- C 派生：父目录失去 PATH_OPEN 后无法再 open；保有 PATH_OPEN 的兄弟目录
  派生出的只读句柄仍无 WRITE。
- D 天花板：base 与 root 同时清零后所有动作拒绝，无法再授予。
- E 重编号：目标先放弃 TELL，源从不持有 TELL；重编号后 TELL 不得复活，
  `fd_tell` 仍 NOTCAPABLE，源槽关闭。
- F 失败原子性：BADF/NOTCAPABLE 失败前后整张描述符表逐字段相等。
- G 关闭：关闭后 BADF，下一次 open 得到新编号，旧编号不回收。

## 三个最小错误恢复变体与失败点

| 补丁 | 通道 | 改动 | 测试失败的精确转换 |
| --- | --- | --- | --- |
| `M_retry-drop-recovery.patch` | 错误重试 | 删除 `fd_fdstat_set_rights` 的子集判断，降权后可直接写回大掩码 | B 段 `T_drop`：重试申请 WRITE 返回 SUCCESS 而非 NOTCAPABLE |
| `M_renumber-rights-union.patch` | 重编号 | T_drop 把移除位藏进 root，T_renumber 再从 root 并回 base | E 段 `T_renumber`：结果掩码超出源掩码，TELL 被复活 |
| `M_derive-overgrant.patch` | 派生句柄 | `path_open` 无视请求，给子句柄 OR 上 FD_WRITE | A/C 段 `T_open`：只读请求产出的句柄 `fd_write` 成功 |

三个变体各自只改动一到两行，且分别在不同命名转换上被独立捕获，
说明测试针对的是具体状态转换，而非返回码统计。
