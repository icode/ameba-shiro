package ameba.security.shiro.internal;

import ameba.message.error.ErrorMessage;
import ameba.message.error.ExceptionMapperUtils;
import com.google.common.hash.Hashing;
import org.apache.shiro.ShiroException;
import org.apache.shiro.authz.UnauthorizedException;

import javax.ws.rs.core.Response;
import javax.ws.rs.ext.ExceptionMapper;

/**
 * @author icode
 */
public class ShiroExceptionMapper implements ExceptionMapper<ShiroException> {

    @Override
    public Response toResponse(ShiroException exception) {

        Response.Status status;

        if (exception instanceof UnauthorizedException) {
            status = Response.Status.UNAUTHORIZED;
        } else {
            status = Response.Status.FORBIDDEN;
        }
        ErrorMessage error = ErrorMessage.fromStatus(status.getStatusCode());
        error.setCode(Hashing.murmur3_32().hashUnencodedChars(exception.getClass().getName()).toString());

        return Response.status(status)
                .type(ExceptionMapperUtils.getResponseType())
                .entity(error)
                .build();
    }
}
