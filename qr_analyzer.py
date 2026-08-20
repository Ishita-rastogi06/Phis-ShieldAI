import cv2
import numpy as np
from PIL import Image

def analyze_qr(image_path):
    """
    Multi-Engine Robust QR Code Decoder.
    Combines ZXing-CPP, PyZbar, and OpenCV with multi-scale image processing.
    """
    # ── 1. Engine 1: ZXing-CPP (Highest accuracy for screenshots & generated QR codes) ──
    try:
        import zxingcpp
        pil_img = Image.open(image_path)
        results = zxingcpp.read_barcodes(pil_img)
        for r in results:
            if r.text and r.text.strip():
                return r.text.strip()
    except Exception:
        pass

    # ── 2. Engine 2: PyZbar ──
    try:
        from pyzbar.pyzbar import decode
        pil_img = Image.open(image_path)
        decoded = decode(pil_img)
        for item in decoded:
            if item.data:
                res = item.data.decode('utf-8', errors='ignore').strip()
                if res:
                    return res
    except Exception:
        pass

    # ── 3. Engine 3: OpenCV with Multi-Scale Pre-Processing ──
    img = cv2.imread(image_path)
    if img is None:
        return None

    detector = cv2.QRCodeDetector()

    # Pass A: Original image
    try:
        data, _, _ = detector.detectAndDecode(img)
        if data and data.strip():
            return data.strip()
    except Exception:
        pass

    # Pass B: Grayscale
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    try:
        data, _, _ = detector.detectAndDecode(gray)
        if data and data.strip():
            return data.strip()
    except Exception:
        pass

    # Pass C: Otsu Thresholding
    try:
        _, thresh = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
        data, _, _ = detector.detectAndDecode(thresh)
        if data and data.strip():
            return data.strip()
    except Exception:
        pass

    # Pass D: Adaptive Thresholding
    try:
        adaptive = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2)
        data, _, _ = detector.detectAndDecode(adaptive)
        if data and data.strip():
            return data.strip()
    except Exception:
        pass

    # Pass E: Scaled Up (2x) for low resolution QR codes
    try:
        h, w = gray.shape[:2]
        scaled = cv2.resize(gray, (w * 2, h * 2), interpolation=cv2.INTER_CUBIC)
        data, _, _ = detector.detectAndDecode(scaled)
        if data and data.strip():
            return data.strip()
    except Exception:
        pass

    # Pass F: Contour Cropping for QR embedded inside large screenshot
    try:
        contours, _ = cv2.findContours(thresh, cv2.RETR_TREE, cv2.CHAIN_APPROX_SIMPLE)
        for cnt in contours:
            area = cv2.contourArea(cnt)
            if area > 1000:
                x, y, cw, ch = cv2.boundingRect(cnt)
                aspect_ratio = float(cw) / ch
                if 0.7 <= aspect_ratio <= 1.3:
                    crop = gray[y:y+ch, x:x+cw]
                    data, _, _ = detector.detectAndDecode(crop)
                    if data and data.strip():
                        return data.strip()
    except Exception:
        pass

    return None