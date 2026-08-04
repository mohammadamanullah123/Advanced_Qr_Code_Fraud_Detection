FROM python:3.9

WORKDIR /app

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all project files
COPY . .

# Expose port 7860 (required by Hugging Face Spaces)
EXPOSE 7860

# Run the Flask app using Gunicorn on port 7860
CMD ["gunicorn", "-b", "0.0.0.0:7860", "-w", "2", "--timeout", "120", "app:app"]
