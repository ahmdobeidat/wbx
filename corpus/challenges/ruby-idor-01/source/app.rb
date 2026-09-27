require 'sinatra'
RECORDS = {}
get '/record/:id' do
  redirect '/login' unless session[:user]
  record = RECORDS[params[:id].to_i]   # IDOR: no owner check
  record.to_json
end
