from stacks.downloader.protection import response_looks_like_protection


def _consume_landing_response(response, fallback_url):
    """Read a landing page and deterministically release its connection."""
    try:
        response.raise_for_status()
        return response.text, response.url or fallback_url
    finally:
        response.close()


def _download_external_link(
    d,
    download_link,
    source_url,
    title,
    resume_attempts,
    md5,
    subfolder,
):
    """Download an external file with the landing page as its Referer."""
    return d.download_direct(
        download_link,
        title=title,
        resume_attempts=resume_attempts,
        md5=md5,
        subfolder=subfolder,
        request_headers={'Referer': source_url},
    )


def download_from_mirror(d, mirror_url, mirror_type, md5, title=None, resume_attempts=3, subfolder=None):
    """
    Download from any mirror with stale cookie handling.

    Logic:
    - slow_download: Use pre-warmed cookies with direct HTTP requests
    - external_mirror: Try direct, use FlareSolverr on protection responses

    Args:
        subfolder: Subfolder path to save file to (optional)
    """
    try:
        if mirror_type == 'slow_download':
            d.logger.debug("Accessing slow download (via cookies)")

            # Try to load cached cookies for this domain (uses current working domain)
            d.load_cached_cookies()

            if hasattr(d, 'status_callback'):
                d.status_callback("Accessing slow download page...")

            try:
                # Try to fetch the slow_download page with cookies
                response = d.session.get(mirror_url, timeout=30)

                # DDoS-Guard can return either an error status or a branded HTTP-200 page.
                if response_looks_like_protection(response):
                    if not d.flaresolverr_url:
                        d.logger.warning(f"Got {response.status_code} but no FlareSolverr configured")
                        return None

                    d.logger.warning(f"Got {response.status_code}, solving challenge with FlareSolverr...")

                    if hasattr(d, 'status_callback'):
                        d.status_callback("Solving CAPTCHA with FlareSolverr...")

                    # Solve challenge for THIS specific URL
                    success, cookies, html_content = d.solve_with_flaresolverr(mirror_url)

                    if not success:
                        d.logger.error("FlareSolverr failed")
                        return None

                    if not html_content:
                        response = d.session.get(mirror_url, timeout=30)
                        if response_looks_like_protection(response):
                            response.close()
                            d.logger.error("Still protected after FlareSolverr solve")
                            return None
                        response.raise_for_status()
                        html_content = response.text

                    if hasattr(d, 'status_callback'):
                        d.status_callback("Extracting download link...")

                    download_link = d.parse_download_link_from_html(html_content, md5, mirror_url)
                    if not download_link:
                        d.logger.warning("Could not find download link")
                        return None

                    if hasattr(d, 'status_callback'):
                        d.status_callback("Downloading file...")

                    d.logger.info("Found download URL via FlareSolverr, downloading...")
                    return d.download_direct(download_link, title=title, resume_attempts=resume_attempts, md5=md5, subfolder=subfolder)

                response.raise_for_status()

                if hasattr(d, 'status_callback'):
                    d.status_callback("Extracting download link...")

                download_link = d.parse_download_link_from_html(response.text, md5, mirror_url)
                if not download_link:
                    d.logger.warning("Could not find download link")
                    return None

                if hasattr(d, 'status_callback'):
                    d.status_callback("Downloading file...")

                d.logger.info("Found download URL, downloading...")
                return d.download_direct(download_link, title=title, resume_attempts=resume_attempts, md5=md5, subfolder=subfolder)

            except Exception as e:
                d.logger.error(f"Error accessing slow_download page: {e}")
                return None
        
        else:  # external_mirror
            d.logger.debug(f"Accessing external mirror: {mirror_url}")

            # Try to load cached cookies for this mirror
            d.load_cached_cookies(domain=mirror_url)

            try:
                response = d.session.get(mirror_url, timeout=30)

                # Solve protection for this external URL directly. Pre-warming
                # Anna's Archive cookies cannot refresh an external domain.
                if response_looks_like_protection(response):
                    status_code = response.status_code
                    response.close()
                    if not d.flaresolverr_url:
                        d.logger.warning(
                            f"Got protection response ({status_code}) but "
                            "FlareSolverr not configured"
                        )
                        return None

                    d.logger.warning(
                        f"Got protection response ({status_code}); solving "
                        "the external URL with FlareSolverr"
                    )
                    if hasattr(d, 'status_callback'):
                        d.status_callback("Solving CAPTCHA with FlareSolverr...")

                    success, _, html_content = d.solve_with_flaresolverr(mirror_url)
                    if not success:
                        return None

                    source_url = mirror_url
                    if not html_content:
                        response = d.session.get(mirror_url, timeout=30)
                        if response_looks_like_protection(response):
                            response.close()
                            d.logger.error("Still protected after FlareSolverr solve")
                            return None
                        html_content, source_url = _consume_landing_response(
                            response,
                            mirror_url,
                        )

                    if hasattr(d, 'status_callback'):
                        d.status_callback("Extracting download link...")
                    download_link = d.parse_download_link_from_html(
                        html_content,
                        md5,
                        source_url,
                    )
                    if not download_link:
                        d.logger.warning("Could not find download link")
                        return None

                    if hasattr(d, 'status_callback'):
                        d.status_callback("Downloading file...")
                    d.logger.info(
                        "Found download URL via FlareSolverr, downloading..."
                    )
                    return _download_external_link(
                        d,
                        download_link,
                        source_url,
                        title,
                        resume_attempts,
                        md5,
                        subfolder,
                    )

                html_content, source_url = _consume_landing_response(
                    response,
                    mirror_url,
                )

                if hasattr(d, 'status_callback'):
                    d.status_callback("Extracting download link...")

                download_link = d.parse_download_link_from_html(
                    html_content,
                    md5,
                    source_url,
                )
                if not download_link:
                    d.logger.warning("Could not find download link")
                    return None

                if hasattr(d, 'status_callback'):
                    d.status_callback("Downloading file...")

                return _download_external_link(
                    d,
                    download_link,
                    source_url,
                    title,
                    resume_attempts,
                    md5,
                    subfolder,
                )

            except Exception as e:
                d.logger.error(f"Error accessing external mirror: {e}")
                return None
    
    except Exception as e:
        d.logger.error(f"Error downloading from mirror: {e}")
        return None
