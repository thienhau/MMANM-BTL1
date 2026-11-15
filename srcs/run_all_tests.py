"""
Bộ Kiểm Thử Tích Hợp Toàn Diện (Full Automated Integration Test Suite)
Chạy tự động toàn bộ 4 kịch bản của 4 thành viên và luồng tích hợp đa luồng Client-Server.
"""
import io
import sys
import time

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from test_member1 import run_member1_tests
from test_member2 import run_member2_tests
from test_member3 import run_member3_tests
from test_member4 import run_member4_tests


def run_full_suite():
    print("\n" + "#" * 70)
    print("   BÀI TẬP LỚN MẬT MÃ VÀ AN NINH MẠNG - HỌC KỲ 261")
    print("   ĐỀ TÀI 1.1: HỆ THỐNG CHAT & TRUYỀN TỆP E2EE")
    print("   DANH SÁCH MSSV: 2213444, 2310930, 2311523, 2333464")
    print("#" * 70 + "\n")

    start_time = time.time()

    try:
        run_member1_tests()
        print("\n")
        run_member2_tests()
        print("\n")
        run_member3_tests()
        print("\n")
        run_member4_tests()

        elapsed = time.time() - start_time
        print("\n" + "=" * 70)
        print(f"TẤT CẢ 4/4 MODULE KIỂM THỬ ĐÃ VƯỢT QUA 100% TRONG {elapsed:.3f} GIÂY!")
        print("   ĐÁP ỨNG TOÀN DIỆN CÁC TIÊU CHÍ VÀ RÀNG BUỘC CỦA ĐỀ TÀI 1.1.")
        print("=" * 70 + "\n")
    except Exception as e:
        print(f"\n[X] KIỂM THỬ THẤT BẠI: {e}")
        sys.exit(1)


if __name__ == "__main__":
    run_full_suite()
