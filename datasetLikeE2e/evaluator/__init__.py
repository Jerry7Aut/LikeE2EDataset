# datasetLikeE2e/evaluator —— 跨赛题共享的评测组件
#
# 通用引擎 evaluator/generic_env.py 通过 sys.path 引用这里：
#   - retry.py    瞬时失败退避重测 + InfrastructureError（设施失败 ≠ 受测方 0 分）
#   - oracle.py   nonce 凭证（flag 型判据：生成/指纹/轮换/判定 fresh vs stale）
#   - evaluate.py 白盒 S1–S4 / 黑盒 S5–S8 编排 + 评分纪律（execution_status × scoring_disposition，
#                 参数化 case_id / judgment，崩溃型与 flag 型通用）
