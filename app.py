from cyber_shield import check_strength, generate_password

# 1. 16 अक्षरांचा सुरक्षित पासवर्ड तयार करा
password = generate_password(length=16)
print("Generated Key:", password)

# 2. कोणत्याही पासवर्डची सुरक्षितता तपासा
report = check_strength("UserPass123!")
print("Strength Level:", report.level)
print("Score:", f"{report.score}/{report.max_score}")
print("Suggestions:", report.feedback)
