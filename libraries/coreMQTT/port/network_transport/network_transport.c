#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include <string.h>
#include "esp_log.h"
#include "esp_tls.h"
#include "esp_err.h"
#include "network_transport.h"
#include "sdkconfig.h"
#include <fcntl.h>
#include <errno.h>
#include "lwip/netdb.h"
#include "lwip/inet.h"

// BIOBOT
#ifndef TLS_IO_RETRY_DELAY_TICKS
    #define TLS_IO_RETRY_DELAY_TICKS    pdMS_TO_TICKS( 1 )
#endif

#ifndef TLS_IO_RETRY_TIMEOUT_MS
    #define TLS_IO_RETRY_TIMEOUT_MS     ( 200U )
#endif
// END OF BIOBOT

static void logResolvedAddress( const char * hostname, int port )
{
    struct addrinfo hints = { 0 };
    struct addrinfo * result = NULL;
    char address[ INET6_ADDRSTRLEN ] = { 0 };
    char service[ 8 ] = { 0 };
    int dnsResult;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    snprintf( service, sizeof( service ), "%d", port );
    dnsResult = getaddrinfo( hostname, service, &hints, &result );

    if( ( dnsResult == 0 ) && ( result != NULL ) )
    {
        const void * binaryAddress = NULL;

        if( result->ai_family == AF_INET )
        {
            binaryAddress = &( ( const struct sockaddr_in * ) result->ai_addr )->sin_addr;
        }
        else if( result->ai_family == AF_INET6 )
        {
            binaryAddress = &( ( const struct sockaddr_in6 * ) result->ai_addr )->sin6_addr;
        }

        if( ( binaryAddress != NULL ) &&
            ( inet_ntop( result->ai_family, binaryAddress, address, sizeof( address ) ) != NULL ) )
        {
            ESP_LOGI( "network_transport", "DNS resolved %s to %s", hostname, address );
        }
        freeaddrinfo( result );
    }
    else
    {
        ESP_LOGE( "network_transport", "DNS resolution failed for %s: code=%d", hostname, dnsResult );
    }
}

static void logTlsErrors( esp_tls_t * tls )
{
    esp_tls_error_handle_t errorHandle = NULL;
    int systemError = 0;
    int mbedtlsError = 0;
    int certFlags = 0;
    int espError = 0;

    if( esp_tls_get_error_handle( tls, &errorHandle ) != ESP_OK )
    {
        ESP_LOGE( "network_transport", "Unable to retrieve ESP-TLS error handle" );
        return;
    }

    ( void ) esp_tls_get_and_clear_error_type( errorHandle, ESP_TLS_ERR_TYPE_SYSTEM, &systemError );
    ( void ) esp_tls_get_and_clear_error_type( errorHandle, ESP_TLS_ERR_TYPE_MBEDTLS, &mbedtlsError );
    ( void ) esp_tls_get_and_clear_error_type( errorHandle, ESP_TLS_ERR_TYPE_MBEDTLS_CERT_FLAGS, &certFlags );
    ( void ) esp_tls_get_and_clear_error_type( errorHandle, ESP_TLS_ERR_TYPE_ESP, &espError );

    ESP_LOGE( "network_transport",
              "TLS connect failed: esp=0x%x (%s), mbedtls=-0x%x, cert_flags=0x%x, errno=%d (%s)",
              espError, esp_err_to_name( espError ), -mbedtlsError, certFlags,
              systemError, strerror( systemError ) );
}

TlsTransportStatus_t xTlsConnect( NetworkContext_t* pxNetworkContext )
{
    TlsTransportStatus_t xRet = TLS_TRANSPORT_SUCCESS;

    esp_tls_cfg_t xEspTlsConfig = {
        .cacert_buf = (const unsigned char*) ( pxNetworkContext->pcServerRootCA ),
        .cacert_bytes = pxNetworkContext->pcServerRootCASize,
        .clientcert_buf = (const unsigned char*) ( pxNetworkContext->pcClientCert ),
        .clientcert_bytes = pxNetworkContext->pcClientCertSize,
        .skip_common_name = pxNetworkContext->disableSni,
        .alpn_protos = pxNetworkContext->pAlpnProtos,
        .use_secure_element = pxNetworkContext->use_secure_element,
        .ds_data = pxNetworkContext->ds_data,
        .clientkey_buf = ( const unsigned char* )( pxNetworkContext->pcClientKey ),
        .clientkey_bytes = pxNetworkContext->pcClientKeySize,
        .timeout_ms = pxNetworkContext->timeout, // BIOBOT, PREV (1000)
        .non_block = false, // BIOBOT: prev was true, but now we set non blocking after handshake is done, to avoid blocking the task indefinitely in case of network issues during handshake
    };

    esp_tls_t* pxTls = esp_tls_init();

    xSemaphoreTake(pxNetworkContext->xTlsContextSemaphore, portMAX_DELAY);
    pxNetworkContext->pxTls = pxTls;

    logResolvedAddress( pxNetworkContext->pcHostname, pxNetworkContext->xPort );

    if (esp_tls_conn_new_sync( pxNetworkContext->pcHostname, 
            strlen( pxNetworkContext->pcHostname ), 
            pxNetworkContext->xPort, 
            &xEspTlsConfig, pxTls) <= 0)
    {
        logTlsErrors( pxNetworkContext->pxTls );
        if (pxNetworkContext->pxTls)
        {
            esp_tls_conn_destroy(pxNetworkContext->pxTls);
            pxNetworkContext->pxTls = NULL;
        }
        xRet = TLS_TRANSPORT_CONNECT_FAILURE;
    }
    else
    {
        // Handshake done on blocking socket; now switch to non-blocking for MQTT send/recv
        int sock = -1;
        if (esp_tls_get_conn_sockfd(pxTls, &sock) == ESP_OK)
        {
            int flags = fcntl(sock, F_GETFL, 0);
            fcntl(sock, F_SETFL, flags | O_NONBLOCK);
        }
    }

    xSemaphoreGive(pxNetworkContext->xTlsContextSemaphore);

    return xRet;
}

TlsTransportStatus_t xTlsDisconnect( NetworkContext_t* pxNetworkContext )
{
    BaseType_t xRet = TLS_TRANSPORT_SUCCESS;

    xSemaphoreTake(pxNetworkContext->xTlsContextSemaphore, portMAX_DELAY);
    if (pxNetworkContext->pxTls != NULL && 
        esp_tls_conn_destroy(pxNetworkContext->pxTls) < 0)
    {
        xRet = TLS_TRANSPORT_DISCONNECT_FAILURE;
    }
    pxNetworkContext->pxTls = NULL;
    xSemaphoreGive(pxNetworkContext->xTlsContextSemaphore);

    return xRet;
}

int32_t espTlsTransportSend(NetworkContext_t* pxNetworkContext,
    const void* pvData, size_t uxDataLen)
{
    if (pvData == NULL || uxDataLen == 0)
    {
        return -1;
    }

    int32_t lBytesSent = 0;

#if 0
    if(pxNetworkContext != NULL && pxNetworkContext->pxTls != NULL)
    {
        xSemaphoreTake(pxNetworkContext->xTlsContextSemaphore, portMAX_DELAY);
        lBytesSent = esp_tls_conn_write(pxNetworkContext->pxTls, pvData, uxDataLen);
        xSemaphoreGive(pxNetworkContext->xTlsContextSemaphore);

        /* BIOBOT BEGIN*/
        if( lBytesSent == ESP_TLS_ERR_SSL_WANT_WRITE ||
           lBytesSent == ESP_TLS_ERR_SSL_WANT_READ )
        {
            return 0; /* retry later in non-blocking mode */
        }
        /* BIOBOT END */
    }
    else
    {
        lBytesSent = -1;
    }
    return lBytesSent;

#else


    if(pxNetworkContext != NULL)
    {
        TickType_t xStartTicks;
        xStartTicks = xTaskGetTickCount();

        for(;;)
        {
            xSemaphoreTake(pxNetworkContext->xTlsContextSemaphore, portMAX_DELAY);
            if (pxNetworkContext->pxTls == NULL)
            {
                xSemaphoreGive(pxNetworkContext->xTlsContextSemaphore);
                return -1;
            }
            lBytesSent = esp_tls_conn_write(pxNetworkContext->pxTls, pvData, uxDataLen);
            xSemaphoreGive(pxNetworkContext->xTlsContextSemaphore);

            if (lBytesSent > 0) 
            {
                return lBytesSent;
            }

            if (lBytesSent == ESP_TLS_ERR_SSL_WANT_WRITE  || lBytesSent == ESP_TLS_ERR_SSL_WANT_READ) 
            {
                if( pdTICKS_TO_MS( xTaskGetTickCount() - xStartTicks ) >= TLS_IO_RETRY_TIMEOUT_MS )
                {
                    /* No progress yet, let coreMQTT retry from sendBuffer/sendMessageVector. */
                    return 0;
                }
                vTaskDelay(TLS_IO_RETRY_DELAY_TICKS); /* retry later in non-blocking mode */
                continue;
            }

            return lBytesSent;
        }
    }
    else
    {
        return -1;
    }
#endif
}

int32_t espTlsTransportRecv(NetworkContext_t* pxNetworkContext,
    void* pvData, size_t uxDataLen)
{
#if 0
    if (pvData == NULL || uxDataLen == 0)
    {
        return -1;
    }
    int32_t lBytesRead = 0;
    if(pxNetworkContext != NULL && pxNetworkContext->pxTls != NULL)
    {
        xSemaphoreTake(pxNetworkContext->xTlsContextSemaphore, portMAX_DELAY);
        lBytesRead = esp_tls_conn_read(pxNetworkContext->pxTls, pvData, uxDataLen);
        xSemaphoreGive(pxNetworkContext->xTlsContextSemaphore);
    }
    else
    {
        return -1; /* pxNetworkContext or pxTls uninitialised */
    }
    if (lBytesRead == ESP_TLS_ERR_SSL_WANT_WRITE  || lBytesRead == ESP_TLS_ERR_SSL_WANT_READ) {
        return 0;
    }
    if (lBytesRead < 0) {
        return lBytesRead;
    }
    if (lBytesRead == 0) {
        /* Connection closed */
        return -1;
    }
    return lBytesRead;
#else   
    // BIOBOT
    if (pvData == NULL || uxDataLen == 0)
    {
        return -1;
    }
    int32_t lBytesRead = 0;
    
    if(pxNetworkContext != NULL)
    {
        TickType_t xStartTicks;

        xStartTicks = xTaskGetTickCount();

        for(;;) 
        {            
            xSemaphoreTake(pxNetworkContext->xTlsContextSemaphore, portMAX_DELAY);
            if (pxNetworkContext->pxTls == NULL)
            {
                xSemaphoreGive(pxNetworkContext->xTlsContextSemaphore);
                return -1;
            }
            lBytesRead = esp_tls_conn_read(pxNetworkContext->pxTls, pvData, uxDataLen);
            xSemaphoreGive(pxNetworkContext->xTlsContextSemaphore);

            if (lBytesRead > 0) 
            {
                return lBytesRead;
            }

            if (lBytesRead == 0)
            {
                return -1; /* Connection closed */
            }

            if (lBytesRead == ESP_TLS_ERR_SSL_WANT_WRITE  || lBytesRead == ESP_TLS_ERR_SSL_WANT_READ) 
            {
                if( pdTICKS_TO_MS( xTaskGetTickCount() - xStartTicks ) >= TLS_IO_RETRY_TIMEOUT_MS )
                {
                    /* No progress yet, let coreMQTT keep polling. */
                    return 0;
                }
                vTaskDelay(TLS_IO_RETRY_DELAY_TICKS); /* retry later in non-blocking mode */
                continue;
            }

            return lBytesRead; /* Return on any other error */
            
        }
    }
    else
    {
        return -1; /* pxNetworkContext or pxTls uninitialised */
    }
    
#endif
}
