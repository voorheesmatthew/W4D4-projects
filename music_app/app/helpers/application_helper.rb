module ApplicationHelper
  def auth_token
    "<input type='hidden' name='authenticity_token' value='<%= form_authenticity_token %>'/>".html_safe
  end

  def patch_method_overide
    "<input type='hidden' name='_method' value='patch'>".html_safe
  end

  def get_method_overide
    "<input type='hidden' name='_method' value='get'>".html_safe
  end

  def delete_method_overide
    "<input type='hidden' name='_method' value='delete'>".html_safe
  end


end
