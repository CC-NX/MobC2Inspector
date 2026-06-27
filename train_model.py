#!/usr/bin/env python3
"""
MobC2Inspector - 恶意C2检测模型训练脚本
========================================
使用随机森林对特征CSV训练C2通信检测模型，输出量化评估指标。

功能：
  1. 读取特征CSV（含正常和C2样本）
  2. 数据预处理与标准化
  3. 训练随机森林分类器
  4. 5折交叉验证评估
  5. 输出准确率、召回率、F1、AUC等指标
  6. 绘制特征重要性柱状图
  7. 保存模型为 c2_model.joblib

用法：
  python train_model.py                          # 使用默认CSV (data/sample_features.csv)
  python train_model.py --csv path/to/data.csv    # 指定CSV路径
  python train_model.py --test                    # 快速测试模式

作者: MobC2Inspector Team
"""

import os
import sys
import json
import argparse
import warnings
import numpy as np
import pandas as pd
from pathlib import Path

warnings.filterwarnings("ignore")


# ============================================================
#  项目路径
# ============================================================
PROJECT_ROOT = Path(__file__).parent
DATA_DIR = PROJECT_ROOT / "data"
MODELS_DIR = PROJECT_ROOT / "models"

# 创建目录
for d in [DATA_DIR, MODELS_DIR]:
    d.mkdir(parents=True, exist_ok=True)

# ============================================================
#  默认特征列
# ============================================================
FEATURE_COLUMNS = [
    "packet_length_entropy",   # 数据包长度信息熵
    "interval_variance",       # 通信间隔方差
    "dns_query_entropy",       # DNS查询域名熵值
    "tls_sni_length",          # TLS SNI长度
    "connection_count",        # 连接总数
    "unique_destinations",     # 唯一目标数
    "avg_packet_len",          # 平均包长度
    "cert_issuer_length"       # 证书颁发者长度
]

LABEL_COLUMN = "label"  # 0=正常, 1=恶意C2


# ============================================================
#  1. 生成示例数据（当CSV不存在时使用）
# ============================================================
def generate_sample_data(n_samples: int = 120, seed: int = 42) -> pd.DataFrame:
    """
    生成跨平台示例特征数据集，包含Android和Windows平台的正常流量与恶意C2流量。
    恶意样本的特征分布与正常样本有明显差异，用于演示模型训练。

    Args:
        n_samples: 样本总数
        seed: 随机种子

    Returns:
        DataFrame: 特征数据集
    """
    np.random.seed(seed)

    n_malicious = n_samples // 2
    n_benign = n_samples - n_malicious

    data = []

    # ----- 恶意C2样本（Android平台） -----
    for i in range(n_malicious // 2):
        session_id = f"C2_{i:03d}"
        row = {
            "session_id": session_id,
            "label": 1,
            "platform": "android",
            "packet_length_entropy": np.random.uniform(6.0, 7.9),
            "interval_variance": np.random.exponential(300),
            "dns_query_entropy": np.random.uniform(3.5, 4.9),
            "tls_sni_length": np.random.randint(8, 25),
            "connection_count": np.random.randint(15, 50),
            "unique_destinations": np.random.randint(1, 4),
            "avg_packet_len": np.random.exponential(600),
            "cert_issuer_length": np.random.randint(15, 40),
            "tls_sni": f"c2{np.random.randint(1000,9999)}.xyz",
            "cipher_suites": "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384",
            "cert_issuer": "CN=UnknownCA",
            "ja3_hash": hashlib.md5(str(np.random.random()).encode()).hexdigest()
        }
        data.append(row)

    # ----- 恶意C2样本（Windows平台，PCAP来源） -----
    for i in range(n_malicious - n_malicious // 2):
        session_id = f"WIN_C2_{i:03d}"
        row = {
            "session_id": session_id,
            "label": 1,
            "platform": "windows",
            # Windows木马C2同样具有高熵值、固定心跳间隔等特征
            "packet_length_entropy": np.random.uniform(6.2, 7.8),
            "interval_variance": np.random.exponential(250),
            "dns_query_entropy": np.random.uniform(3.8, 5.0),
            "tls_sni_length": np.random.randint(10, 22),
            "connection_count": np.random.randint(20, 55),
            "unique_destinations": np.random.randint(1, 3),
            "avg_packet_len": np.random.exponential(650),
            "cert_issuer_length": np.random.randint(12, 35),
            "tls_sni": f"win-update{np.random.randint(1000,9999)}.darknet",
            "cipher_suites": "TLS_AES_128_GCM_SHA256,TLS_CHACHA20_POLY1305_SHA256",
            "cert_issuer": "CN=DarkNetCA",
            "ja3_hash": hashlib.md5(str(np.random.random()).encode()).hexdigest()
        }
        data.append(row)

    # ----- 正常流量样本（Android平台） -----
    for i in range(n_benign // 2):
        session_id = f"BENIGN_{i:03d}"
        row = {
            "session_id": session_id,
            "label": 0,
            "platform": "android",
            "packet_length_entropy": np.random.uniform(2.5, 5.0),
            "interval_variance": np.random.exponential(1500),
            "dns_query_entropy": np.random.uniform(1.0, 3.0),
            "tls_sni_length": np.random.randint(15, 50),
            "connection_count": np.random.randint(1, 12),
            "unique_destinations": np.random.randint(3, 12),
            "avg_packet_len": np.random.exponential(300),
            "cert_issuer_length": np.random.randint(50, 120),
            "tls_sni": f"www.{random_company()}.com",
            "cipher_suites": "TLS_AES_128_GCM_SHA256,TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
            "cert_issuer": f"CN={random_company()} Root CA",
            "ja3_hash": hashlib.md5(str(np.random.random()).encode()).hexdigest()
        }
        data.append(row)

    # ----- 正常流量样本（Windows平台，PCAP来源） -----
    for i in range(n_benign - n_benign // 2):
        session_id = f"WIN_BENIGN_{i:03d}"
        row = {
            "session_id": session_id,
            "label": 0,
            "platform": "windows",
            "packet_length_entropy": np.random.uniform(2.8, 4.8),
            "interval_variance": np.random.exponential(1800),
            "dns_query_entropy": np.random.uniform(1.2, 2.8),
            "tls_sni_length": np.random.randint(20, 45),
            "connection_count": np.random.randint(2, 10),
            "unique_destinations": np.random.randint(4, 10),
            "avg_packet_len": np.random.exponential(280),
            "cert_issuer_length": np.random.randint(60, 130),
            "tls_sni": f"www.{random_company()}.com",
            "cipher_suites": "TLS_AES_128_GCM_SHA256",
            "cert_issuer": f"CN={random_company()} Corp CA",
            "ja3_hash": hashlib.md5(str(np.random.random()).encode()).hexdigest()
        }
        data.append(row)

    df = pd.DataFrame(data)
    return df

import hashlib
import random

_companies = ["google", "facebook", "microsoft", "apple", "amazon",
              "cloudflare", "github", "gitlab", "twitter", "linkedin",
              "baidu", "alibaba", "tencent", "netflix", "spotify"]

def random_company():
    return random.choice(_companies)


# ============================================================
#  2. 训练与评估
# ============================================================
def train_and_evaluate(df: pd.DataFrame, feature_cols: list,
                       label_col: str, save_model: bool = True,
                       output_plot: bool = True) -> dict:
    """
    训练随机森林分类器并输出评估指标。

    Args:
        df: 特征DataFrame
        feature_cols: 特征列名列表
        label_col: 标签列名
        save_model: 是否保存模型
        output_plot: 是否生成特征重要性图

    Returns:
        dict: 评估指标
    """
    from sklearn.model_selection import cross_val_predict, StratifiedKFold, train_test_split
    from sklearn.preprocessing import StandardScaler
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import (
        accuracy_score, precision_score, recall_score,
        f1_score, roc_auc_score, confusion_matrix,
        classification_report, roc_curve
    )

    # 提取特征和标签
    X = df[feature_cols].values
    y = df[label_col].values

    # 处理缺失值
    X = np.nan_to_num(X, nan=0.0)

    # 标准化
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    print(f"[*] 数据集: {X.shape[0]} 样本, {X.shape[1]} 特征")
    print(f"[*] 恶意样本: {int(y.sum())}, 正常样本: {int((1-y).sum())}")
    print(f"[*] 恶意比例: {y.mean():.1%}")
    print()

    # ----- 训练随机森林 -----
    model = RandomForestClassifier(
        n_estimators=100,
        max_depth=10,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )

    # 5折交叉验证
    cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)

    print("=" * 60)
    print("5折交叉验证评估结果")
    print("=" * 60)

    fold_metrics = []
    for fold, (train_idx, test_idx) in enumerate(cv.split(X_scaled, y), 1):
        X_train, X_test = X_scaled[train_idx], X_scaled[test_idx]
        y_train, y_test = y[train_idx], y[test_idx]

        model.fit(X_train, y_train)
        y_pred = model.predict(X_test)
        y_proba = model.predict_proba(X_test)[:, 1]

        fold_acc = accuracy_score(y_test, y_pred)
        fold_prec = precision_score(y_test, y_pred, zero_division=0)
        fold_rec = recall_score(y_test, y_pred, zero_division=0)
        fold_f1 = f1_score(y_test, y_pred, zero_division=0)
        fold_auc = roc_auc_score(y_test, y_proba)
        cm = confusion_matrix(y_test, y_pred)

        fold_metrics.append({
            "fold": fold,
            "accuracy": fold_acc,
            "precision": fold_prec,
            "recall": fold_rec,
            "f1": fold_f1,
            "auc": fold_auc,
            "tn": cm[0][0] if cm.shape == (2,2) else 0,
            "fp": cm[0][1] if cm.shape == (2,2) else 0,
            "fn": cm[1][0] if cm.shape == (2,2) else 0,
            "tp": cm[1][1] if cm.shape == (2,2) else 0
        })

        print(f"\n  Fold {fold}:")
        print(f"    ACC={fold_acc:.4f}  PRE={fold_prec:.4f}  REC={fold_rec:.4f}  "
              f"F1={fold_f1:.4f}  AUC={fold_auc:.4f}")
        print(f"    Confusion Matrix: [[{cm[0][0]} {cm[0][1]}] [{cm[1][0]} {cm[1][1]}]]")

    # ----- 汇总指标 -----
    print("\n" + "=" * 60)
    print("汇总指标（5折平均）")
    print("=" * 60)

    avg_metrics = {}
    for metric in ["accuracy", "precision", "recall", "f1", "auc"]:
        values = [m[metric] for m in fold_metrics]
        avg_metrics[metric] = np.mean(values)
        avg_metrics[f"{metric}_std"] = np.std(values)
        print(f"  {metric.upper():15s}: {np.mean(values):.4f} ± {np.std(values):.4f}")

    # 平均混淆矩阵
    avg_tp = np.mean([m["tp"] for m in fold_metrics])
    avg_fp = np.mean([m["fp"] for m in fold_metrics])
    avg_tn = np.mean([m["tn"] for m in fold_metrics])
    avg_fn = np.mean([m["fn"] for m in fold_metrics])
    fpr = avg_fp / (avg_fp + avg_tn) if (avg_fp + avg_tn) > 0 else 0

    print(f"\n  平均混淆矩阵:")
    print(f"    [[{avg_tn:.0f} {avg_fp:.0f}]")
    print(f"     [{avg_fn:.0f} {avg_tp:.0f}]]")
    print(f"  误报率(FPR): {fpr:.4f}")

    # ----- 全量训练模型 -----
    model.fit(X_scaled, y)
    y_pred_all = cross_val_predict(model, X_scaled, y, cv=cv, method="predict")
    y_proba_all = cross_val_predict(model, X_scaled, y, cv=cv, method="predict_proba")[:, 1]

    print("\n" + "=" * 60)
    print("分类报告（全量交叉验证）")
    print("=" * 60)
    print(classification_report(y, y_pred_all, target_names=["Benign", "C2"], zero_division=0))

    # ----- 保存模型 -----
    if save_model:
        import joblib
        model_path = MODELS_DIR / "c2_model.joblib"
        # 保存时附上scaler
        model_data = {
            "model": model,
            "scaler": scaler,
            "feature_columns": feature_cols,
            "training_metrics": avg_metrics,
            "model_type": "RandomForest"
        }
        joblib.dump(model_data, str(model_path))
        print(f"\n[+] 模型已保存: {model_path}")

        # 也保存纯模型（便于直接加载）
        joblib.dump(model, str(MODELS_DIR / "c2_model_pure.joblib"))
        print(f"[+] 纯模型已保存: {MODELS_DIR / 'c2_model_pure.joblib'}")

    # ----- 特征重要性图 -----
    if output_plot and hasattr(model, "feature_importances_"):
        try:
            import matplotlib
            matplotlib.use("Agg")
            import matplotlib.pyplot as plt

            importances = model.feature_importances_
            indices = np.argsort(importances)[::-1]

            plt.figure(figsize=(12, 7))
            plt.title("恶意C2通信检测 - 特征重要性排序", fontsize=14, fontweight="bold")
            bars = plt.bar(range(len(importances)), importances[indices],
                          align="center", color=["#E74C3C" if i < 3 else "#3498DB"
                                                  for i in range(len(importances))])

            plt.xticks(range(len(importances)),
                      [feature_cols[i] for i in indices],
                      rotation=45, ha="right", fontsize=11)

            plt.ylabel("重要性得分", fontsize=12)
            plt.xlabel("特征", fontsize=12)
            plt.grid(axis="y", alpha=0.3)

            # 在柱状图上标注数值
            for i, bar in enumerate(bars):
                plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.005,
                        f"{importances[indices[i]]:.3f}",
                        ha="center", va="bottom", fontsize=9)

            plt.tight_layout()
            plot_path = DATA_DIR / "feature_importance.png"
            plt.savefig(str(plot_path), dpi=150, bbox_inches="tight")
            plt.close()
            print(f"[+] 特征重要性图已保存: {plot_path}")
        except ImportError:
            print("[!] matplotlib未安装，跳过特征重要性图")
        except Exception as e:
            print(f"[!] 绘图失败: {e}")

    # ----- 构造返回 -----
    result = {
        "model_path": str(MODELS_DIR / "c2_model.joblib"),
        "feature_importance_plot": str(DATA_DIR / "feature_importance.png"),
        "total_samples": len(y),
        "malicious_count": int(y.sum()),
        "benign_count": int((1 - y).sum()),
        "metrics": {
            "accuracy": round(avg_metrics["accuracy"], 4),
            "accuracy_std": round(avg_metrics["accuracy_std"], 4),
            "precision": round(avg_metrics["precision"], 4),
            "precision_std": round(avg_metrics["precision_std"], 4),
            "recall": round(avg_metrics["recall"], 4),
            "recall_std": round(avg_metrics["recall_std"], 4),
            "f1_score": round(avg_metrics["f1"], 4),
            "f1_std": round(avg_metrics["f1_std"], 4),
            "roc_auc": round(avg_metrics["auc"], 4),
            "auc_std": round(avg_metrics["auc_std"], 4),
            "false_positive_rate": round(fpr, 4),
            "avg_true_positive": int(avg_tp),
            "avg_false_positive": int(avg_fp),
            "avg_true_negative": int(avg_tn),
            "avg_false_negative": int(avg_fn)
        },
        "features_used": feature_cols,
        "fold_details": fold_metrics,
        "classification_report": classification_report(
            y, y_pred_all, target_names=["Benign", "C2"],
            output_dict=True, zero_division=0
        )
    }

    return result


# ============================================================
#  主入口
# ============================================================
def main():
    parser = argparse.ArgumentParser(
        description="MobC2Inspector - 恶意C2检测模型训练"
    )
    parser.add_argument("--csv", type=str, default=str(DATA_DIR / "sample_features.csv"),
                       help="特征CSV路径 (默认: data/sample_features.csv)")
    parser.add_argument("--test", action="store_true",
                       help="快速测试：仅使用20条样本")
    parser.add_argument("--no-save", action="store_true",
                       help="不保存模型")
    parser.add_argument("--no-plot", action="store_true",
                       help="不生成特征重要性图")

    args = parser.parse_args()

    csv_path = args.csv

    # 读取或生成数据
    if os.path.exists(csv_path):
        print(f"[*] 读取特征数据: {csv_path}")
        df = pd.read_csv(csv_path)
    else:
        print(f"[*] CSV不存在 ({csv_path})，生成示例数据...")
        df = generate_sample_data(n_samples=20 if args.test else 100)
        df.to_csv(csv_path, index=False)
        print(f"[+] 示例数据已保存: {csv_path}")

    # 确认特征列存在
    available_features = [c for c in FEATURE_COLUMNS if c in df.columns]
    if len(available_features) < 3:
        print(f"[!] 特征列不足，使用所有数值列")
        available_features = df.select_dtypes(include=[np.number]).columns.tolist()
        if LABEL_COLUMN in available_features:
            available_features.remove(LABEL_COLUMN)

    # 处理缺失值
    for col in available_features:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    # 测试模式：仅20条
    if args.test:
        df = df.head(20)

    # 训练与评估
    result = train_and_evaluate(
        df,
        feature_cols=available_features,
        label_col=LABEL_COLUMN,
        save_model=not args.no_save,
        output_plot=not args.no_plot
    )

    # 输出JSON摘要
    print("\n" + "=" * 60)
    print("评估结果JSON")
    print("=" * 60)
    print(json.dumps({
        "metrics": result["metrics"],
        "total_samples": result["total_samples"],
        "malicious_count": result["malicious_count"],
        "benign_count": result["benign_count"]
    }, indent=2, ensure_ascii=False))

    print(f"\n[+] 模型文件: {result['model_path']}")
    print(f"[+] 特征重要性图: {result['feature_importance_plot']}")
    print("[+] 训练完成!")


if __name__ == "__main__":
    main()
