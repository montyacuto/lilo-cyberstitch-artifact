package org.owasp.benchmark.testcode;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class BenchmarkTest00089 extends HttpServlet {
  protected void doPost(HttpServletRequest request, HttpServletResponse response)
      throws SQLException {
    Connection connection = Database.open();
    Statement statement = connection.createStatement();
    String data = request.getParameter("user");
    statement.execute("select * from users where name = '" + data + "'");
  }
}
