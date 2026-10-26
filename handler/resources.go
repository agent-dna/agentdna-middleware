package handler

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

const (
	listPageSize    = 10
	listMaxPageSize = 100
)

// listPage reads a 1-based page and its size from pageKey / sizeKey.
// The size is capped so one request cannot pull a whole list.
func listPage(c *gin.Context, pageKey, sizeKey string) (page, pageSize int) {
	page = 1
	if p, err := strconv.Atoi(c.Query(pageKey)); err == nil && p > 0 {
		page = p
	}
	pageSize = listPageSize
	if ps, err := strconv.Atoi(c.Query(sizeKey)); err == nil && ps > 0 {
		pageSize = min(ps, listMaxPageSize)
	}
	return page, pageSize
}

func pageInfo(total, page, pageSize int) gin.H {
	return gin.H{
		"total":      total,
		"page":       page,
		"pageSize":   pageSize,
		"totalPages": (total + pageSize - 1) / pageSize,
	}
}

// ResourcesList handles GET /dashboard/v1/resources-list?page=&pageSize=:
// every resource, most-used first.
func (h *Handler) ResourcesList(c *gin.Context) {
	page, pageSize := listPage(c, "page", "pageSize")

	total, err := h.db.CountResources()
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to count resources: %v", err)})
		return
	}
	resources, err := h.db.ListResources(pageSize, (page-1)*pageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch resources: %v", err)})
		return
	}

	list := make([]gin.H, 0, len(resources))
	for _, r := range resources {
		list = append(list, gin.H{
			"resourceID":      r.ID,
			"name":            r.Name,
			"url":             r.ID,
			"intentCount":     r.IntentCount,
			"credentialCount": r.CredentialCount,
		})
	}
	data := pageInfo(total, page, pageSize)
	data["resourcesList"] = list
	c.JSON(http.StatusOK, Response{Status: true, Data: data})
}

// ResourceInfo handles GET /dashboard/v1/resource-info?resourceID=
// &intentsPage=&intentsPageSize=&credentialsPage=&credentialsPageSize=:
// one resource with a page of the intents that reached it and a page of
// the credentials they used. The two lists page independently.
func (h *Handler) ResourceInfo(c *gin.Context) {
	resourceID := c.Query("resourceID")
	if resourceID == "" {
		c.JSON(http.StatusBadRequest, Response{Status: false, Message: "resourceID is required"})
		return
	}

	resource, err := h.db.GetResource(resourceID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch resource: %v", err)})
		return
	}
	if resource == nil {
		c.JSON(http.StatusNotFound, Response{Status: false, Message: "resource not found"})
		return
	}

	intentsPage, intentsPageSize := listPage(c, "intentsPage", "intentsPageSize")
	intents, err := h.db.GetResourceIntents(resourceID, intentsPageSize, (intentsPage-1)*intentsPageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch resource intents: %v", err)})
		return
	}
	credentialsPage, credentialsPageSize := listPage(c, "credentialsPage", "credentialsPageSize")
	credentials, err := h.db.GetResourceCredentials(resourceID, credentialsPageSize, (credentialsPage-1)*credentialsPageSize)
	if err != nil {
		c.JSON(http.StatusInternalServerError, Response{Status: false, Message: fmt.Sprintf("failed to fetch resource credentials: %v", err)})
		return
	}

	intentList := make([]gin.H, 0, len(intents))
	for _, i := range intents {
		var startedAt any
		if i.StartedAt.Valid {
			startedAt = i.StartedAt.Time
		}
		credentialIDs := i.CredentialIDs
		if credentialIDs == nil {
			credentialIDs = []string{}
		}
		intentList = append(intentList, gin.H{
			"intentID":       i.IntentID,
			"initiatorDID":   i.InitiatorDID,
			"initiatorName":  i.InitiatorName,
			"status":         i.Status,
			"reviewStatus":   i.ReviewStatus,
			"flowType":       i.FlowType,
			"threatDetected": i.ThreatDetected,
			"startedAt":      startedAt,
			"credentialIDs":  credentialIDs,
		})
	}
	credentialList := make([]gin.H, 0, len(credentials))
	for _, cr := range credentials {
		credentialList = append(credentialList, gin.H{
			"credentialID": cr.CredentialID,
			"authMethod":   cr.AuthMethod,
			"intentCount":  cr.IntentCount,
			"status":       cr.Status,
		})
	}

	intentsData := pageInfo(resource.IntentCount, intentsPage, intentsPageSize)
	intentsData["list"] = intentList
	credentialsData := pageInfo(resource.CredentialCount, credentialsPage, credentialsPageSize)
	credentialsData["list"] = credentialList

	c.JSON(http.StatusOK, Response{Status: true, Data: gin.H{
		"resourceID":      resource.ID,
		"name":            resource.Name,
		"url":             resource.ID,
		"intentCount":     resource.IntentCount,
		"credentialCount": resource.CredentialCount,
		"intents":         intentsData,
		"credentials":     credentialsData,
	}})
}
