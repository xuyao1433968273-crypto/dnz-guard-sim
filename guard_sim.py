# -*- coding: utf-8 -*-
"""
保安 vs 房东 —— 内存"双视图"原理模拟器
========================================
纯教学演示程序，不涉及真实内存、不涉及虚拟化、不针对任何反作弊。

角色设定：
    房东   = 住在暗处的人，手里有一本"楼层图"（能控制每个房间给谁看什么）
    游戏   = 大楼的住户，正常使用房间
    保安   = dnz，负责查房，检查有没有人藏东西

核心剧情：
    有些房间被房东装了"双面镜"：
       - 游戏来读  -> 看到"改过版"（比如藏着自瞄代码的房间）
       - 保安来查  -> 房东翻镜子，保安看到"干净版"（一切正常）
    保安每次来查，房东还偷偷记下"翻镜子花了多久"（防时间差检测的雏形）。

运行：python guard_sim.py
"""
import time

# ------------------------------------------------------------------
# 道具：一个房间（一页内存）
# ------------------------------------------------------------------
class Room:
    def __init__(self, name, clean, modified, has_mirror=False):
        self.name = name                # 房间名
        self.clean = clean              # 干净版内容（给保安看的）
        self.modified = modified        # 改过版内容（给游戏用的）
        self.has_mirror = has_mirror    # 是否装了双面镜
        self.scan_count = 0             # 被保安查过几次

# ------------------------------------------------------------------
# 大楼：所有房间
# ------------------------------------------------------------------
class Building:
    def __init__(self):
        self.rooms = [
            Room("客厅",    clean="沙发+电视",             modified="沙发+电视",        has_mirror=False),
            Room("书房",    clean="书架+书桌",             modified="书架+书桌",        has_mirror=False),
            Room("游戏房",  clean="空荡荡的普通房间",      modified="藏着一套自瞄代码", has_mirror=True),
            Room("仓库",    clean="堆放普通杂物",          modified="藏着一批作弊工具", has_mirror=True),
        ]

    def find(self, name):
        for r in self.rooms:
            if r.name == name:
                return r
        return None

# ------------------------------------------------------------------
# 房东：控制每个房间给谁看什么
# ------------------------------------------------------------------
class Landlord:
    def __init__(self, building):
        self.building = building
        self.timing_log = []            # 每次翻镜子记下的耗时
        self.mirror_flips = 0           # 总共翻了几次镜子

    def handle_read(self, who, room):
        """有人来读房间了。房东决定给他看哪一面。"""
        if not room.has_mirror:
            # 没装双面镜的房间，谁看都一样
            print(f"    [{who}] 走进【{room.name}】，看到：{room.clean}")
            return room.clean

        if who == "保安dnz":
            # 保安来查房 -> 翻镜子，给干净版
            self.mirror_flips += 1
            room.scan_count += 1
            elapsed = self._flip_mirror()          # 翻镜子耗时
            self.timing_log.append(elapsed)        # 记账（防时间差）
            print(f"    [保安dnz] 来查【{room.name}】→ 房东翻镜子(第{self.mirror_flips}次, 耗时{elapsed}纳秒)")
            print(f"             保安看到的房间：{room.clean}   ← 一切正常！")
            return room.clean
        else:
            # 游戏来读 -> 给改过版
            print(f"    [{who}] 走进【{room.name}】，看到：{room.modified}")
            return room.modified

    def _flip_mirror(self):
        """翻镜子的动作，模拟需要一点点时间。"""
        start = time.perf_counter_ns()
        # 模拟翻镜子的微小开销
        for _ in range(1000):
            pass
        end = time.perf_counter_ns()
        return end - start

# ------------------------------------------------------------------
# 主角登场，开始演
# ------------------------------------------------------------------
def main():
    print("=" * 60)
    print("       保安 vs 房东：双视图原理模拟")
    print("=" * 60)
    print("房东装好了大楼。有 4 个房间：客厅、书房、游戏房、仓库。")
    print("其中【游戏房】和【仓库】装了双面镜。\n")

    building = Building()
    landlord = Landlord(building)

    print(">>> 场景 1：游戏正常玩，读自己的房间\n")
    landlord.handle_read("游戏", building.find("客厅"))
    landlord.handle_read("游戏", building.find("游戏房"))
    landlord.handle_read("游戏", building.find("仓库"))

    print("\n>>> 场景 2：保安 dnz 开始查房（每秒都在查）\n")
    for i in range(3):
        print(f"--- 第 {i+1} 轮查房 ---")
        for room in building.rooms:
            landlord.handle_read("保安dnz", room)
        print()

    print(">>> 场景 3：保安查完走了，游戏继续用改过版\n")
    landlord.handle_read("游戏", building.find("游戏房"))
    landlord.handle_read("游戏", building.find("仓库"))

    print("=" * 60)
    print("总结")
    print("=" * 60)
    print(f"  保安共查了 {sum(r.scan_count for r in building.rooms)} 次房，一次都没发现异常")
    print(f"  房东共翻了 {landlord.mirror_flips} 次镜子")
    print(f"  每次翻镜子的耗时记录（房东的小账本）：{landlord.timing_log[:6]}")
    print("\n  关键点：保安每秒都在查，但它的每一眼都经过房东。")
    print("  房东让它看到干净版，它就觉得一切正常。")
    print("  这，就是'双视图'的全部秘密。")

if __name__ == "__main__":
    main()
