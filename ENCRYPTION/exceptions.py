# ------------------------------- START OF LICENSE NOTICE -----------------------------
# Copyright (c) 2019 Soroco Private Limited ("Soroco").
#
# NO WARRANTY. THE PRODUCT IS PROVIDED BY SOROCO "AS IS" AND ANY EXPRESS OR IMPLIED
# WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY
# AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL SOROCO BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
# DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
# NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THE PRODUCT, EVEN IF
# ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
# -------------------------------- END OF LICENSE NOTICE ------------------------------
"""Contains exceptions thrown by this package."""


class ScreenshotException(Exception):
    """Base exception class raised by soroco.screenshot."""

    pass


class MultipleSetupException(ScreenshotException):
    """Raised when :func:`Screenshot.setup` is called more than once."""

    pass


class NotSetupException(ScreenshotException):
    """Raised when functions are called without setting up Screenshot class."""

    pass


class CaptureFailedException(ScreenshotException):
    """Raised when capturing a screenshot fails."""

    pass


class InvalidSubdirPathException(ScreenshotException):
    """Raised when given subdir is not actually a subdirectory of screenshot dir."""

    pass
