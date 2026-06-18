from PIL import Image
import pytesseract

brands = [
    "google",
    "paypal",
    "amazon",
    "microsoft",
    "apple",
    "facebook"
]

def detect_brand_from_image(image):

    text = pytesseract.image_to_string(image)

    for brand in brands:

        if brand in text.lower():

            return brand

    return None