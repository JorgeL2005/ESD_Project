import face_recognition

# 1. Cargar las imágenes
foto_control = face_recognition.load_image_file("foto_dni.jpg")
foto_prueba = face_recognition.load_image_file("foto_selfie.jpg")

# 2. Obtener los "encodings" (los patrones matemáticos de la cara)
# Asumimos que hay una cara en la foto, por eso tomamos el índice [0]
encoding_control = face_recognition.face_encodings(foto_control)[0]
encoding_prueba = face_recognition.face_encodings(foto_prueba)[0]

# 3. Comparar
resultados = face_recognition.compare_faces([encoding_control], encoding_prueba)

if resultados[0]:
    print("¡Es la misma persona!")
else:
    print("Son personas diferentes.")