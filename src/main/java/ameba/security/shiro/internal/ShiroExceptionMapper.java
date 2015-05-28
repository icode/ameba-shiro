package ameba.security.shiro.internal;

import ameba.message.error.ErrorMessage;
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
            status = Response.Status.FORBIDDEN;
        } else {
            status = Response.Status.UNAUTHORIZED;
        }

        return Response.status(status).entity(ErrorMessage.fromStatus(status.getStatusCode())).build();
    }
}
