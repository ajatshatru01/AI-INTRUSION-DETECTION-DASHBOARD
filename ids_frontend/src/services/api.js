const API_BASE_URL = "http://localhost:8000";

export const uploadCSV = async (file) => {
    const formData = new FormData();
    formData.append("file", file);

    try {
        const response = await fetch(`${API_BASE_URL}/analyze_csv`, {
            method: "POST",
            body: formData,
        });

        if (!response.ok) {
            const errorData = await response.json();
            throw new Error(errorData.detail || "Upload failed");
        }

        return await response.json();
    } catch (error) {
        console.error("Error uploading CSV:", error);
        throw error;
    }
};
