import os
from vapt_framework.analytics.risk_matrix import RiskMatrixEngine
from vapt_framework.analytics.attack_matrix import AttackMatrixEngine

class MatrixExporter:
    """
    Saves generated matrices into reports/generated/
    """

    @staticmethod
    def export_all(output_dir: str):
        os.makedirs(output_dir, exist_ok=True)

        risk_engine = RiskMatrixEngine()
        with open(os.path.join(output_dir, "risk_matrix.csv"), "w", encoding="utf-8") as f:
            f.write(risk_engine.to_csv())
        with open(os.path.join(output_dir, "risk_matrix.json"), "w", encoding="utf-8") as f:
            f.write(risk_engine.to_json())
        with open(os.path.join(output_dir, "risk_matrix.md"), "w", encoding="utf-8") as f:
            f.write(risk_engine.to_markdown())

        attack_engine = AttackMatrixEngine()
        with open(os.path.join(output_dir, "attack_matrix.csv"), "w", encoding="utf-8") as f:
            f.write(attack_engine.to_csv())
        with open(os.path.join(output_dir, "attack_matrix.json"), "w", encoding="utf-8") as f:
            f.write(attack_engine.to_json())
        with open(os.path.join(output_dir, "attack_matrix.md"), "w", encoding="utf-8") as f:
            f.write(attack_engine.to_markdown())

        print(f"Successfully exported all matrix files to {output_dir}")
