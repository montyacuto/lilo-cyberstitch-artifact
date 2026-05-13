package org.owasp.benchmark.testcode;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class BenchmarkTest00090 extends HttpServlet {
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
      throws SQLException {
    Connection connection = Database.open();
    String data = request.getParameter("user");
    PreparedStatement statement =
        connection.prepareStatement("select * from users where name = ?");
    statement.setString(1, data);
    statement.execute();
  }
}
