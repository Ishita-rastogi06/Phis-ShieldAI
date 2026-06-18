import cv2

def analyze_qr(image_path):

    detector = cv2.QRCodeDetector()

    data, bbox, _ = detector.detectAndDecode(
        cv2.imread(image_path)
    )

    if not data:
        return None

    return data