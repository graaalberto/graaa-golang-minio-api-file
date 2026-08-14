func (h *FileHandler) UploadFile(c *gin.Context) {
	user := h.getUserClaims(c)
	if user == nil {
		return
	}

	header, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Success: false,
			Error:   "Campo 'file' é obrigatório no formulário multipart",
			Code:    "FILE_REQUIRED",
		})
		return
	}

	isPublic := c.PostForm("is_public") == "true"
	rawTags := c.PostForm("tags")
	var tags []string
	if rawTags != "" {
		for _, t := range strings.Split(rawTags, ",") {
			trimmed := strings.TrimSpace(t)
			if trimmed != "" {
				tags = append(tags, trimmed)
			}
		}
	}

	res, err := h.service.UploadFile(c.Request.Context(), header, user, h.cfg.MinioDefaultBucket, isPublic, tags)
	if err != nil {
		h.logger.Warnw("Falha no upload de arquivo", "user", user.Email, "error", err)
		c.JSON(http.StatusBadRequest, model.ErrorResponse{
			Success: false,
			Error:   err.Error(),
			Code:    "UPLOAD_FAILED",
		})
		return
	}

	c.JSON(http.StatusCreated, model.SuccessResponse{
		Success: true,
		Message: "Arquivo enviado com sucesso para o MinIO",
		Data:    res,
	})
}